#define _GNU_SOURCE /* EFD_CLOEXEC */
/*
 * fwd/dp_dpdk.c -- DPDK data plane for the r2dp forwarder: ports, workers,
 * probe/start/stop and the fwd_dp vtable (dp.h).
 * 
 * The rest of the data plane lives beside it, sharing dpdk_int.h:
 *   dpdk_sad.c    SA table and inbound SAD
 *   dpdk_spd.c    policy snapshot, rte_acl OUT classifier, inbound index
 *   dpdk_esp.c    ESP in/out, crypto batching, anti-replay, NAT-T
 *   dpdk_stats.c  counters
 * 
 * Only compiled when -Denable_dpdk is on (meson gates it).
 * 
 * MT: the control thread (r2dp socket) installs SAs/SPs under d->lock and
 * publishes them with release stores; workers read them lock-free and report
 * QSBR quiescent states so retired memory is freed only after a grace period.
 */
#ifdef R2DP_HAVE_DPDK

#include "dpdk_int.h"
#include <sys/eventfd.h>
#include <unistd.h>

static struct fwd_dp_ops dpdk_ops;

/* nh.wanted: a queued learn is applied only for a current tunnel peer */
static int
nh_wanted(void *arg, uint32_t ip)
{
	return is_tunnel_peer(arg, ip);
}



static inline int
is_esp(struct rte_mbuf *mb)
{
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)
	    ((uint8_t *)rte_pktmbuf_mtod(mb, uint8_t *) + RTE_ETHER_HDR_LEN);
	if (rte_pktmbuf_pkt_len(mb) < RTE_ETHER_HDR_LEN +
	    sizeof(struct rte_ipv4_hdr))
		return 0;
	return (ip->version_ihl >> 4) == 4 && ip->next_proto_id == IPPROTO_ESP;
}

/* ESP-in-UDP on the NAT-T port.  The framing alone decides (RFC 3948): an
 * unknown SPI is then an ordinary SAD miss, dropped as no_sa_in, not
 * cleartext for the exception path. */
static inline int
is_nat_esp(struct rte_mbuf *mb)
{
	return natt_class(rte_pktmbuf_mtod(mb, const uint8_t *),
	    rte_pktmbuf_data_len(mb)) == NT_ESP;
}

static inline int
is_udp(struct rte_mbuf *mb)
{
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)
	    ((uint8_t *)rte_pktmbuf_mtod(mb, uint8_t *) + RTE_ETHER_HDR_LEN);
	if (rte_pktmbuf_pkt_len(mb) < RTE_ETHER_HDR_LEN +
	    sizeof(struct rte_ipv4_hdr))
		return 0;
	return (ip->version_ihl >> 4) == 4 && ip->next_proto_id == IPPROTO_UDP;
}

/* True for the M1 exception-path permit set: ARP, or IPv4 UDP to the IKE
 * ports (500 / 4500 NAT-T).  Everything else from the network must have
 * arrived protected and is dropped (H2). */
static int
is_ike_arp(struct rte_mbuf *mb)
{
	struct rte_ipv4_hdr *ip;
	uint8_t *p;
	uint16_t dport;
	int ihl;

	if (rte_pktmbuf_pkt_len(mb) < RTE_ETHER_HDR_LEN)
		return 0;
	/* ARP: ether_type 0x0806, no IPv4 header to parse */
	p = rte_pktmbuf_mtod(mb, uint8_t *);
	if (p[12] == 0x08 && p[13] == 0x06)
		return 1;
	/* not IPv4 (0x0800) -> not on the IKE/UDP permit path */
	if (p[12] != 0x08 || p[13] != 0x00)
		return 0;
	if (rte_pktmbuf_pkt_len(mb) < RTE_ETHER_HDR_LEN +
	    sizeof(struct rte_ipv4_hdr))
		return 0;
	ip = (struct rte_ipv4_hdr *)(p + RTE_ETHER_HDR_LEN);
	if ((ip->version_ihl >> 4) != 4 || ip->next_proto_id != IPPROTO_UDP)
		return 0;
	ihl = (ip->version_ihl & 0x0f) * 4;
	if (ihl < (int)sizeof(struct rte_ipv4_hdr))
		return 0;
	/* UDP header after the IPv4 header: dst port at +2 */
	{
		const uint8_t *u = p + RTE_ETHER_HDR_LEN + ihl;
		if ((size_t)(u - p) + 4 > rte_pktmbuf_pkt_len(mb))
			return 0;
		dport = (u[2] << 8) | u[3];
	}
	return dport == 500 || dport == 4500;
}

/* Weak so test programs that link the modules without dp.c resolve it; the
 * forwarder's strong definition lives in dp.c. */
__attribute__((weak)) volatile sig_atomic_t fwd_stats_req;

/* rte_eth_tx_burst, but never with zero packets: some PMDs (net_memif's
 * copy path reads bufs[0]->pool before it looks at nb_pkts) dereference
 * the first slot regardless, and every caller here can end up with an
 * empty array -- e.g. a burst whose packets all lacked a next hop. */
static inline uint16_t
port_tx(uint16_t port, uint16_t q, struct rte_mbuf **pkts, uint16_t n)
{
	return n ? rte_eth_tx_burst(port, q, pkts, n) : 0;
}

/* Learn the peer's MAC (keyed by its IP) only from unicast IKE/ESP whose
 * source is a configured tunnel peer, so an arbitrary host on the segment
 * cannot capture egress ESP; relearn when the peer's MAC changes (N1).
 * Called by the lcore that receives on the outer port (the table also
 * serializes writers itself). */
/* Per-burst memo: a burst is mostly one peer, and a repeat of the
 * previous frame's (source IP, source MAC) would change nothing -- skip its peer check and table scan. */
struct nh_memo {
	uint64_t mac;
	uint32_t sip;
	int      valid;
};

static void
nh_learn_frame(struct dpdk_priv *d, struct rte_mbuf *m, struct nh_memo *mo)
{
	uint32_t sip;
	const uint8_t *smac;
	uint64_t mac = 0;
	int lr;

	if (!r2dp_nh_frame_ike_esp(rte_pktmbuf_mtod(m, const uint8_t *),
	    rte_pktmbuf_data_len(m), &sip, &smac))
		return;
	memcpy(&mac, smac, 6);
	if (mo->valid && mo->sip == sip && mo->mac == mac)
		return;
	mo->sip = sip;
	mo->mac = mac;
	mo->valid = 1;
	if (!is_tunnel_peer(d, sip))
		return;
	lr = r2dp_nh_learn(&d->nh, sip, smac);
	if (lr > 0 && d->verbose)
		fprintf(stderr, "r2dp-fwd: %s next hop for peer %08x: "
		    "%02x:%02x:%02x:%02x:%02x:%02x\n",
		    lr == 2 ? "relearned" : "learned", sip, smac[0], smac[1],
		    smac[2], smac[3], smac[4], smac[5]);
}

/* Process a burst received on the OUTER tap (ESP side): ESP -> decrypt ->
 * forward the inner (cleartext) packet out the inner tap; non-ESP (IKE, ARP)
 * is the exception path and crosses to the inner (kernel) side.
 *
 * Classify ONCE into separate arrays.  Compacting in place
 * (bufs[nesp]=bufs[i]) overwrites the slots that still hold unclassified
 * mbufs, and re-scanning bufs[] afterwards re-reads ESP mbufs that
 * esp_inbound() already stripped and freed -- a doble-handling/double-free.
 * Never touch bufs[] again after the single pass below. */

static void
outer_burst(struct dp_wk *w, struct rte_mbuf *bufs[], uint16_t nr, int port,
    int learn)
{
	struct dpdk_priv *d = w->d;
	struct rte_mbuf *esp[BURST_SZ], *exc[BURST_SZ];

	if (d->verbose) {
		/* Dump the first raw frame as the tap delivered it, BEFORE any L2
		 * strip, so we can compare it byte-for-byte against what was
		 * injected (esp.bin wrapped in eth).  If these don't match, the
		 * tap/framing assumption is wrong and every offset downstream is
		 * garbage. */
		struct rte_mbuf *f = bufs[0];
		uint8_t *fr = rte_pktmbuf_mtod(f, uint8_t *);
		uint32_t fl = rte_pktmbuf_pkt_len(f);
		fprintf(stderr, "r2dp-fwd: RX raw pkt_len=%u data_len=%u data_off=%u: ",
		    fl, (unsigned)rte_pktmbuf_data_len(f),
		    (unsigned)rte_pktmbuf_headroom(f));
		for (uint32_t z = 0; z < 40 && z < fl; z++)
			fprintf(stderr, "%02x", fr[z]);
		fprintf(stderr, "\n");
	}
	uint16_t nesp = 0, nex = 0;
	struct nh_memo mo = { .valid = 0 };
	for (uint16_t i = 0; i < nr; i++) {
		if (learn)
			nh_learn_frame(d, bufs[i], &mo);
		if (natt_class(rte_pktmbuf_mtod(bufs[i], const uint8_t *),
		    rte_pktmbuf_data_len(bufs[i])) == NT_KEEPALIVE) {
			w->n_natt_keepalive++;      /* RFC 3948 s2.3: discard */
			rte_pktmbuf_free(bufs[i]);
			continue;
		}
		if (is_esp(bufs[i]) || is_nat_esp(bufs[i])) {
			w->n_esp++;
			esp[nesp++] = bufs[i];
		} else {
			exc[nex++] = bufs[i];
		}
	}

	if (nesp) {
		struct rte_mbuf *dec[BURST_SZ];
		uint16_t ndec = 0;
		esp_inbound(w, esp, nesp, dec, &ndec);
		if (ndec) {
			/* rte_ipsec_pkt_process leaves the decrypted INNER packet as
			 * bare IP (l2_len=0, no Ethernet header).  net_tap transmits
			 * the mbuf into the kernel tap as an Ethernet frame, so a
			 * header must be prepended or the tap sees a frameless
			 * <64-byte packet and the peer never receives the inner
			 * IP.  Fabricate a minimal eth header (dummy MACs -- the
			 * next hop reads the inner IP; this matches ipsec-secgw's
			 * tunneled-inner handling). */
			for (uint16_t i = 0; i < ndec; i++) {
				struct rte_ether_hdr *eh;
				char *h = rte_pktmbuf_prepend(dec[i],
				    RTE_ETHER_HDR_LEN);
				if (h == NULL) {   /* no headroom: drop */
					DROP(w, DR_NOMEM, 1);
					rte_pktmbuf_free(dec[i]);
					dec[i] = NULL;
					continue;
				}
				eh = rte_pktmbuf_mtod(dec[i],
				    struct rte_ether_hdr *);
				/* Deliver each decrypted inner packet UNICAST to the inner
				 * (plaintext host) tap's own MAC.  A broadcast dst here
				 * makes the host kernel classify the frame PACKET_BROADCAST,
				 * and Linux tcp_v4_rcv drops pkt_type != PACKET_HOST
				 * before counting InSegs -- so TCP over the tunnel would
				 * silently never handshake while UDP/ICMP (which accept
				 * broadcast) passed.  icmp/udp also work unicast. */
				{
					memset(eh->dst_addr.addr_bytes, 0,
					    RTE_ETHER_ADDR_LEN);
					memcpy(eh->dst_addr.addr_bytes, d->our_inner_mac, 6);
					memset(eh->src_addr.addr_bytes, 0,
					    RTE_ETHER_ADDR_LEN);
					memcpy(eh->src_addr.addr_bytes, d->our_inner_mac, 6);
				}
				eh->ether_type = htons(RTE_ETHER_TYPE_IPV4);
				dec[i]->l2_len = RTE_ETHER_HDR_LEN;
				/* bump l3_len so inner IP is at eth+ip */
				dec[i]->l3_len = 20;
				/* Linux tap drops Ethernet frames shorter than the
				 * 60-byte (non-VLAN) minimum.  A 44-byte decrypted ICMP
				 * + 14 eth = 58, so pad the L2 frame to 60. */
				{
					uint32_t cur = rte_pktmbuf_pkt_len(dec[i]);
					uint32_t need = RTE_ETHER_MIN_LEN;
					if (cur < need) {
						void *pad = rte_pktmbuf_append(dec[i],
						    need - cur);
						if (pad)
							memset(pad, 0, need - cur);
					}
				}
			}
			uint16_t to = (d->inner_port >= 0) ? d->inner_port : port;
			uint16_t ntx = 0;
			struct rte_mbuf *txq[BURST_SZ];
			for (uint16_t i = 0; i < ndec; i++)
				if (dec[i])
					txq[ntx++] = dec[i];
			uint16_t sent = port_tx(to, w->txq, txq, ntx);
			w->n_tx += sent;
			DROP(w, DR_TX_FULL, ntx - sent);
			if (d->verbose)
				fprintf(stderr, "r2dp-fwd: esp-tx ndec=%u ntx=%u sent=%u\n",
				    ndec, ntx, sent);
			for (uint16_t i = sent; i < ntx; i++)
				rte_pktmbuf_free(txq[i]);
		}
		/* esp_inbound owns and frees every ESP mbuf (matched or not). */
	}
	/* non-ESP: exception path -> the kernel side.  H2: don't fail open --
	 * only IKE (UDP 500/4500) and ARP cross; other cleartext from the network
	 * (which should have arrived under an IN PROTECT SA) is dropped. */
	if (nex) {
		uint16_t to = (d->inner_port >= 0) ? d->inner_port : port;
		uint16_t nf = 0;
		struct rte_mbuf *fwd[BURST_SZ];
		/* Classify once and settle every pointer here: rejected
		 * frames are freed now, permitted ones go to TX.  Nothing in
		 * exc[] is read again -- after TX the PMD owns (and may have
		 * recycled) the sent frames (WORKER W1). */
		for (uint16_t i = 0; i < nex; i++) {
			if (is_ike_arp(exc[i])) {
				fwd[nf++] = exc[i];
			} else {
				DROP(w, DR_CLEAR_OUTER, 1);
				rte_pktmbuf_free(exc[i]);
			}
		}
		if (nf) {
			/* Count IKE per-frame: only a UDP-headed frame is IKE
			 * (the burst may mix ARP; ARP is a clear_outer-free "ok"). */
			for (uint16_t i = 0; i < nf; i++)
				if (is_udp(fwd[i]))
					w->n_ike++;
			uint16_t sent = port_tx(to, w->txq, fwd, nf);
			w->n_tx += sent;
			DROP(w, DR_TX_FULL, nf - sent);
			for (uint16_t i = sent; i < nf; i++)
				rte_pktmbuf_free(fwd[i]);
		}
	}
}

/* Process a burst received on the INNER tap (plaintext/kernel side):
 * protected IPv4 gets encrypted by esp_outbound (EGRESS) and tx'd to the outer
 * tap as ESP; non-protected (IKE/ARP, or no OUT policy -> bypass) crosses to
 * the outer (peer) tap on the exception path.  ESP arriving here is dropped. */
static void
inner_burst(struct dp_wk *w, struct rte_mbuf *bufs[], uint16_t nr, int port)
{
	struct dpdk_priv *d = w->d;

	/* 1. classify: ESP here is anomalous -> drop; non-ESP may be protected
	 *    (encrypt) or unprotected (IKE/ARP -> exception path). */
	struct rte_mbuf *nonesp[BURST_SZ];
	uint16_t nnon = 0;
	for (uint16_t i = 0; i < nr; i++) {
		if (is_esp(bufs[i])) {
			DROP(w, DR_ESP_ON_INNER, 1);
			rte_pktmbuf_free(bufs[i]);
		}
		else
			nonesp[nnon++] = bufs[i];
	}
	if (nnon == 0)
		return;

	/* 2. encrypt the protected subset.  esp_outbound consumes the mbufs with
	 *    a matching OUT policy into esp_out[] (as ESP datagrams, no L2) and
	 *    leaves the unmatched ones (nby) untouched in nonesp[]. */
	struct rte_mbuf *esp_out[BURST_SZ];
	uint16_t nout = 0, nby = 0;
	esp_outbound(w, nonesp, nnon, esp_out, &nout, &nby);

	/* 3. prepend L2 to the ESP datagrams and tx to the outer (peer) tap */
	if (nout) {
		uint16_t ntx = 0;
		struct rte_mbuf *txq[BURST_SZ];
		uint16_t to = (d->port_id >= 0) ? d->port_id : port;
		/* Egress ESP is unicast to the tunnel peer's learned next
		 * hop (keyed by the outer destination IP).  With no learned
		 * MAC, drop: broadcasting ESP would spray it to every host
		 * on the segment (N2).  One lock-free bulk lookup per burst,
		 * over its distinct destinations (mostly one peer). */
		uint32_t udst[BURST_SZ];
		uint64_t umac[BURST_SZ], uhit;
		uint8_t  ui[BURST_SZ];
		unsigned nu = 0;
		for (uint16_t i = 0; i < nout; i++) {
			const struct rte_ipv4_hdr *oip = rte_pktmbuf_mtod(
			    esp_out[i], const struct rte_ipv4_hdr *);
			uint32_t odst;
			unsigned u;
			memcpy(&odst, &oip->dst_addr, 4);
			if (nu && udst[nu - 1] == odst)
				u = nu - 1;
			else {
				for (u = 0; u < nu && udst[u] != odst; u++)
					;
				if (u == nu)
					udst[nu++] = odst;
			}
			ui[i] = (uint8_t)u;
		}
		uhit = r2dp_nh_lookup_bulk(&d->nh, udst, nu, umac);
		for (uint16_t i = 0; i < nout; i++) {
			struct rte_ether_hdr *eh;
			if (!(uhit >> ui[i] & 1)) {
				DROP(w, DR_NO_NEXTHOP, 1);
				rte_pktmbuf_free(esp_out[i]);
				continue;
			}
			if (!rte_pktmbuf_prepend(esp_out[i], RTE_ETHER_HDR_LEN)) {
				DROP(w, DR_NOMEM, 1);
				rte_pktmbuf_free(esp_out[i]);
				continue;
			}
			eh = rte_pktmbuf_mtod(esp_out[i], struct rte_ether_hdr *);
			memcpy(eh->dst_addr.addr_bytes, &umac[ui[i]], 6);
			memcpy(eh->src_addr.addr_bytes, d->our_mac, 6);
			eh->ether_type = htons(RTE_ETHER_TYPE_IPV4);
			esp_out[i]->l2_len = RTE_ETHER_HDR_LEN;
			esp_out[i]->l3_len = 20;
			{   /* pad to Ethernet minimum (tap drops short frames) */
				uint32_t cur = rte_pktmbuf_pkt_len(esp_out[i]);
				if (cur < RTE_ETHER_MIN_LEN) {
					void *pad = rte_pktmbuf_append(esp_out[i],
					    RTE_ETHER_MIN_LEN - cur);
					if (pad) memset(pad, 0, RTE_ETHER_MIN_LEN - cur);
				}
			}
			txq[ntx++] = esp_out[i];
		}
		uint16_t sent = port_tx(to, w->txq, txq, ntx);
		w->n_tx += sent;
		DROP(w, DR_TX_FULL, ntx - sent);
		if (d->verbose)
			fprintf(stderr, "r2dp-fwd: egress-tx nout=%u ntx=%u sent=%u\n",
			    nout, ntx, sent);
		for (uint16_t i = sent; i < ntx; i++)
			rte_pktmbuf_free(txq[i]);
	}

	/* 4. exception path: the unmatched non-ESP packets (IKE/ARP/clear bypass)
	 *    cross to the outer (peer) tap as-is.  These are the nby mbufs still
	 *    held in nonesp[] (esp_outbound did not consume them). */
	if (nby) {
		uint16_t ntx = 0;
		struct rte_mbuf *txq[BURST_SZ];
		uint16_t to = (d->port_id >= 0) ? d->port_id : port;
		/* esp_outbound NULLs every slot it consumed or dropped, so
		 * the survivors are exactly the bypass set (O(n), was O(n^2)) */
		for (uint16_t i = 0; i < nnon; i++)
			if (nonesp[i] != NULL)
				txq[ntx++] = nonesp[i];
		/* count per frame: a bypass burst can mix IKE with other
		 * clear traffic (WORKER W7) */
		for (uint16_t i = 0; i < ntx; i++)
			if (is_udp(txq[i]))
				w->n_ike++;
		uint16_t sent = port_tx(to, w->txq, txq, ntx);
		w->n_tx += sent;
		DROP(w, DR_TX_FULL, ntx - sent);
		for (uint16_t i = sent; i < ntx; i++)
			rte_pktmbuf_free(txq[i]);
	}
}

/* SIGUSR1 dump and the ~1 s summary line; run by one lcore only (the
 * worker with one worker, else the dispatcher). */
static void
housekeeping(struct dpdk_priv *d, uint64_t *last_t)
{
	uint64_t now = rte_rdtsc();

	if (fwd_stats_req) {
		fwd_stats_req = 0;
		dpd_stats_dump(d, stderr);
	}
	if (!*last_t) {
		*last_t = now;
	} else if (now - *last_t >= rte_get_timer_hz()) {
		struct dp_wk t;

		dpd_stats_sum(d, &t);
		fprintf(stderr,
		    "r2dp-fwd: stats rx=%llu tx=%llu esp=%llu ike=%llu drop=%llu\n",
		    (unsigned long long)t.n_rx, (unsigned long long)t.n_tx,
		    (unsigned long long)t.n_esp, (unsigned long long)t.n_ike,
		    (unsigned long long)t.n_drop);
		*last_t = now;
	}
}

static void
qsbr_online(struct dpdk_priv *d, unsigned tid)
{
	if (!d->rcu)
		return;
	rte_rcu_qsbr_thread_register(d->rcu, tid);
	rte_rcu_qsbr_thread_online(d->rcu, tid);
}

static void
qsbr_offline(struct dpdk_priv *d, unsigned tid)
{
	if (d->rcu)
		rte_rcu_qsbr_thread_offline(d->rcu, tid);
}

/* Packet worker.  One worker polls queue 0 itself.  Several workers each
 * poll their own RX queue and process a packet in place when they own its
 * SA.  A packet for another worker is enqueued to that worker's ring
 * (multi-producer: any worker may cross-post).  There is no dispatcher
 * lcore.  The e2e memif sweep showed one: a dispatcher that touched every
 * packet made -n 2 slower than -n 1 at 1400 B even with 1000 tunnels.
 * Replay and the outbound sequence stay single-writer because only the
 * owner calls esp_inbound/esp_outbound. */
static void
cross_post(struct dp_wk *w, struct rte_ring *r, struct rte_mbuf **m,
    uint16_t n)
{
	unsigned sent;

	if (!n)
		return;
	sent = rte_ring_mp_enqueue_burst(r, (void **)m, n, NULL);
	if (sent < n) {
		DROP(w, DR_STEER, n - sent);
		rte_pktmbuf_free_bulk(&m[sent], n - sent);
	}
}

/* RX one queue, learn next hops here (the receiver is the writer that
 * saw the frame), drop NAT keepalives, process what this worker owns,
 * cross-post the rest.  outer=1 is the ESP port. */
static void
rx_owned(struct dp_wk *w, uint16_t port, int outer)
{
	struct dpdk_priv *d = w->d;
	struct rte_mbuf *bufs[BURST_SZ], *mine[BURST_SZ];
	struct rte_mbuf *q[DP_MAX_WK][BURST_SZ];
	uint16_t nq[DP_MAX_WK] = { 0 };
	uint8_t tw[BURST_SZ];
	uint16_t nr, nk = 0, nm = 0;
	struct nh_memo mo = { .valid = 0 };

	nr = rte_eth_rx_burst(port, w->id, bufs, BURST_SZ);
	if (!nr)
		return;
	w->n_rx += nr;
	for (uint16_t i = 0; i < nr; i++) {
		if (outer) {
			nh_learn_frame(d, bufs[i], &mo);
			if (natt_class(rte_pktmbuf_mtod(bufs[i], const uint8_t *),
			    rte_pktmbuf_data_len(bufs[i])) == NT_KEEPALIVE) {
				w->n_natt_keepalive++;
				rte_pktmbuf_free(bufs[i]);
				continue;
			}
		}
		bufs[nk++] = bufs[i];
	}
	if (!nk)
		return;
	if (outer)
		w->n_misplaced += dp_steer_outer(d, bufs, nk, tw, w->id);
	else
		dp_steer_inner(d, bufs, nk, tw);
	for (uint16_t i = 0; i < nk; i++) {
		uint8_t t = tw[i];

		if (t >= d->nb_wk)
			t = 0;
		if (t == w->id)
			mine[nm++] = bufs[i];
		else
			q[t][nq[t]++] = bufs[i];
	}
	if (nm) {
		if (outer)
			outer_burst(w, mine, nm, port, 0);
		else
			inner_burst(w, mine, nm, port);
	}
	for (unsigned t = 0; t < d->nb_wk; t++) {
		if (!nq[t])
			continue;
		cross_post(w, outer ? d->wk[t].ring_o : d->wk[t].ring_i,
		    q[t], nq[t]);
	}
}

static int
worker_main(void *arg)
{
	struct dp_wk *w = arg;
	struct dpdk_priv *d = w->d;
	int port = d->port_id, single = d->nb_wk == 1;
	struct rte_mbuf *bufs[BURST_SZ];
	uint64_t last_t = 0;

	fprintf(stderr, "r2dp-fwd: worker %u on lcore %u, outer=%d inner=%d "
	    "txq=%u cqp=%u\n", w->id, rte_lcore_id(), port, d->inner_port,
	    w->txq, w->cqp);
	qsbr_online(d, w->lcore);
	while (__atomic_load_n(&d->running, __ATOMIC_RELAXED)) {
		uint16_t nr;

		if (single) {
			nr = rte_eth_rx_burst(port, 0, bufs, BURST_SZ);
			if (nr) {
				w->n_rx += nr;
				outer_burst(w, bufs, nr, port, 1);
			}
			if (d->inner_port >= 0 &&
			    (nr = rte_eth_rx_burst(d->inner_port, 0, bufs,
			    BURST_SZ)) != 0) {
				w->n_rx += nr;
				inner_burst(w, bufs, nr, d->inner_port);
			}
		} else {
			/* Drain what other workers cross-posted BEFORE this
			 * worker's own RX burst: those frames arrived earlier,
			 * so an SA whose packets come in on several queues is
			 * reordered by at most about one burst, not a ring's
			 * depth, and in-window packets are not mistaken for
			 * replays (REPLAY R1). */
			nr = rte_ring_sc_dequeue_burst(w->ring_o, (void **)bufs,
			    BURST_SZ, NULL);
			if (nr)
				outer_burst(w, bufs, nr, port, 0);
			nr = rte_ring_sc_dequeue_burst(w->ring_i, (void **)bufs,
			    BURST_SZ, NULL);
			if (nr)
				inner_burst(w, bufs, nr,
				    d->inner_port >= 0 ? d->inner_port : port);
			rx_owned(w, (uint16_t)port, 1);
			if (d->inner_port >= 0)
				rx_owned(w, (uint16_t)d->inner_port, 0);
		}
		/* hand a stuck device's late completions back even when no
		 * traffic arrives to trigger it (WORKER W2) */
		if (unlikely(w->cq_stale))
			(void)crypto_drain_stale(w);
		if (d->rcu)
			rte_rcu_qsbr_quiescent(d->rcu, w->lcore);
		if (w->id == 0)
			housekeeping(d, &last_t);
	}
	qsbr_offline(d, w->lcore);
	return 0;
}

/* Port TX queues / cryptodev queue pairs available for workers. */
static unsigned
max_workers(struct dpdk_priv *d)
{
	unsigned n = DP_MAX_WK;
	int ports[2] = { d->port_id, d->inner_port };

	for (int i = 0; i < 2; i++) {
		struct rte_eth_dev_info di;
		if (ports[i] >= 0 && rte_eth_dev_info_get(ports[i], &di) == 0)
			n = RTE_MIN(n, (unsigned)di.max_tx_queues);
	}
	if (d->have_cdev)
		n = RTE_MIN(n, (unsigned)d->cdev_info.max_nb_queue_pairs);
	return n ? n : 1;
}

/* Launch nb_wk workers on the EAL worker lcores.  Each polls RX queue
 * `id` and processes packets it owns in place.  nb_wk was fixed at probe
 * time, before any SA could be installed, because it decides the
 * least-loaded assignment.  No dispatcher lcore. */
static int
dpd_start(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;
	unsigned lc[DP_MAX_WK + 1], nlc = 0, need, lcore;
	int ret = 0;

	if (d->port_id < 0)
		return -ENODEV;
	if (d->running)
		return -EBUSY;
	need = d->nb_wk;
	RTE_LCORE_FOREACH_WORKER(lcore) {
		if (nlc == need)
			break;
		lc[nlc++] = lcore;
	}
	if (nlc < need) {
		fprintf(stderr, "r2dp-fwd: %u worker(s) need %u spare lcores, "
		    "have %u (e.g. -l 0-%u)\n", d->nb_wk, need, nlc, need);
		ret = -EAGAIN;
		goto rollback;
	}
	ret = dp_port_init(d, d->port_id, d->nb_wk);
	if (ret < 0)
		goto rollback;
	{
		uint16_t mtu = 0;
		if (rte_eth_dev_get_mtu(d->port_id, &mtu) == 0)
			d->out_mtu = mtu;
	}
	/* inner (plaintext) tap is optional: single-tap mode (interop lab,
	 * control-only) has only the outer port */
	if (d->inner_port >= 0) {
		int r = dp_port_init(d, d->inner_port, d->nb_wk);
		if (r < 0) {
			fprintf(stderr, "r2dp-fwd: inner port %d init failed (%s); "
			    "running single-port\n", d->inner_port, rte_strerror(-r));
			d->inner_port = -1;
		}
	}
	/* H5: QSBR so the ctl (main) thread can free SA/SP memory only after
	 * every reader has passed a grace period -- the workers read
	 * sa_tab/sp_tab and hold session pointers across their crypto path
	 * with no lock.  tid = lcore id (< RTE_MAX_LCORE). */
	if (!d->rcu) {   /* kept across stop/start: the next-hop table is
			  * attached to it */
		size_t rsz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
		d->rcu = rte_zmalloc("r2dp-rcu", rsz, RTE_CACHE_LINE_SIZE);
		if (!d->rcu) {
			fprintf(stderr, "r2dp-fwd: rte_rcu_qsbr alloc failed\n");
			ret = -ENOMEM;
			goto rollback;
		}
		rte_rcu_qsbr_init(d->rcu, RTE_MAX_LCORE);
	}
	/* next-hop table: lock-free readers, grown off the data path by its
	 * own maintenance thread, retired tables freed through the same
	 * QSBR (dpdk_nh.h) */
	if (!d->nh.h) {
		int r = r2dp_nh_init(&d->nh, "r2dp_nh", d->nh_size, d->rcu,
		    SOCKET_ID_ANY);
		if (r == 0) {
			d->nh.wanted = nh_wanted;
			d->nh.wanted_arg = d;
			r = r2dp_nh_start(&d->nh);
		}
		if (r < 0) {
			fprintf(stderr, "r2dp-fwd: next-hop table: %s\n",
			    strerror(-r));
			ret = r;
			goto rollback;
		}
	} else {
		/* stop/start cycle: the table and its hash survived dpd_stop,
		 * but the maintenance thread was stopped with it.  Re-arm it. */
		d->nh.wanted = nh_wanted;
		d->nh.wanted_arg = d;
		if (r2dp_nh_start(&d->nh) < 0) {
			fprintf(stderr, "r2dp-fwd: next-hop table restart: %s\n",
			    strerror(errno));
			ret = -EAGAIN;
			goto rollback;
		}
	}
	for (unsigned i = 0; i < d->nb_wk; i++) {
		dp_wk_init(d, i);
		d->wk[i].lcore = lc[i];
	}
	if (d->nb_wk > 1)
		for (unsigned i = 0; i < d->nb_wk; i++) {
			char n[RTE_RING_NAMESIZE];
			snprintf(n, sizeof(n), "r2dp_ro%u", i);
			/* MP/SC: any worker may cross-post; only this worker dequeues. */
			d->wk[i].ring_o = rte_ring_create(n, DP_RING_SZ,
			    SOCKET_ID_ANY, RING_F_SC_DEQ);
			snprintf(n, sizeof(n), "r2dp_ri%u", i);
			d->wk[i].ring_i = rte_ring_create(n, DP_RING_SZ,
			    SOCKET_ID_ANY, RING_F_SC_DEQ);
			if (!d->wk[i].ring_o || !d->wk[i].ring_i) {
				fprintf(stderr, "r2dp-fwd: worker ring: %s\n",
				    rte_strerror(rte_errno));
				ret = -ENOMEM;
				goto rollback;
			}
		}
	{	/* our MACs, for the L2 headers the workers write */
		struct rte_ether_addr ea;
		if (rte_eth_macaddr_get(d->port_id, &ea) == 0)
			memcpy(d->our_mac, ea.addr_bytes, 6);
		if (d->inner_port >= 0 &&
		    rte_eth_macaddr_get(d->inner_port, &ea) == 0)
			memcpy(d->our_inner_mac, ea.addr_bytes, 6);
	}
	if (rte_lcore_count() > 1 + need)
		fprintf(stderr, "r2dp-fwd: %u lcores given, %u used (-n %u)\n",
		    rte_lcore_count(), 1 + need, d->nb_wk);
	d->running = 1;
	for (unsigned i = 0; i < d->nb_wk; i++)
		rte_eal_remote_launch(worker_main, &d->wk[i], d->wk[i].lcore);
	return 0;

rollback:
	/* A start failure must not leave a half-started dataplane: ports live
	 * with nobody polling them, an NH maintenance thread armed, rings
	 * half-created.  Tear down exactly what this call set up, then return
	 * the error so the caller (probe) reports "unavailable" instead of
	 * serving SAs/SPs against a dead data plane. */
	__atomic_store_n(&d->running, 0, __ATOMIC_RELAXED);
	if (d->nh.h)
		r2dp_nh_stop(&d->nh);
	for (unsigned i = 0; i < d->nb_wk; i++) {
		struct dp_wk *w = &d->wk[i];
		struct rte_mbuf *m;

		if (w->lcore < RTE_MAX_LCORE) {
			rte_eal_wait_lcore(w->lcore);
			if (d->rcu)
				rte_rcu_qsbr_thread_unregister(d->rcu, w->lcore);
		}
		while (w->ring_o && rte_ring_dequeue(w->ring_o, (void **)&m) == 0)
			rte_pktmbuf_free(m);
		rte_ring_free(w->ring_o);
		w->ring_o = NULL;
		while (w->ring_i && rte_ring_dequeue(w->ring_i, (void **)&m) == 0)
			rte_pktmbuf_free(m);
		rte_ring_free(w->ring_i);
		w->ring_i = NULL;
		w->lcore = RTE_MAX_LCORE;
	}
	if (d->port_id >= 0) {
		rte_eth_dev_stop(d->port_id);
		d->port_id = -1;
	}
	if (d->inner_port >= 0) {
		rte_eth_dev_stop(d->inner_port);
		d->inner_port = -1;
	}
	return ret < 0 ? ret : -EIO;    /* a rollback is never a success */
}

static void
dpd_stop(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;

	__atomic_store_n(&d->running, 0, __ATOMIC_RELAXED);
	/* Phase 1: bring every worker to a stop FIRST.  A still-running worker
	 * can cross-post into another worker's ring, so all workers must be
	 * quiesced before any ring is freed -- freeing ring j while worker i
	 * is enqueuing to it is a use-after-free.  Also unregister them from
	 * the QSBR (the ctl thread below runs grace periods before freeing). */
	for (unsigned i = 0; i < d->nb_wk; i++) {
		struct dp_wk *w = &d->wk[i];

		if (w->lcore < RTE_MAX_LCORE) {
			rte_eal_wait_lcore(w->lcore);
			if (d->rcu)
				rte_rcu_qsbr_thread_unregister(d->rcu, w->lcore);
		}
	}
	/* Stop the next-hop maintenance thread while the QSBR is still alive:
	 * its per-iteration r2dp_qsbr_sync() runs on this same object, and its
	 * wanted() callback reads the policy snapshot (is_tunnel_peer) which
	 * spd_teardown() frees below. */
	if (d->nh.h)
		r2dp_nh_stop(&d->nh);
	/* Phase 2: no producers remain; drain and free the rings. */
	for (unsigned i = 0; i < d->nb_wk; i++) {
		struct dp_wk *w = &d->wk[i];
		struct rte_mbuf *m;

		while (w->ring_o && rte_ring_dequeue(w->ring_o, (void **)&m) == 0)
			rte_pktmbuf_free(m);
		while (w->ring_i && rte_ring_dequeue(w->ring_i, (void **)&m) == 0)
			rte_pktmbuf_free(m);
		rte_ring_free(w->ring_o);
		rte_ring_free(w->ring_i);
		w->ring_o = w->ring_i = NULL;
	}
	/* Keep the QSBR across a stop/start cycle: the next-hop table (d->nh)
	 * is attached to it (its maintenance thread runs grace periods over
	 * this object and its freed tables are returned through it), so
	 * freeing it here would leave d->nh.rcu dangling on restart.  It is
	 * released when the whole dpdk_priv is torn down (main exit). */
	if (d->expire_fd > 0) {
		close(d->expire_fd);
		d->expire_fd = -1;
		dp->wake_fd = -1;
	}
	spd_teardown(d);
}

/* ------------------------------------------------------------------ */
/* Lookaside crypto: AES-NI multi-buffer when the EAL was given one
 * (--vdev=crypto_aesni_mb0), else OpenSSL.  One queue pair per worker. */
static int
crypto_init(struct dpdk_priv *d)
{
	static const char *const names[] = {
		"crypto_aesni_mb0", "crypto_aesni_mb", "crypto_openssl0",
		"crypto_openssl",
	};
	struct rte_cryptodev_config cconf;
	struct rte_cryptodev_qp_conf qconf;
	int id = -1;

	for (size_t i = 0; i < RTE_DIM(names) && id < 0; i++)
		id = rte_cryptodev_get_dev_id(names[i]);
	if (id < 0) {
		fprintf(stderr, "r2dp-fwd: warning: no crypto device; add "
		    "--vdev crypto_openssl0 (or crypto_aesni_mb0) for AES-GCM\n");
		return -ENODEV;
	}
	d->cdev_id = (uint8_t)id;
	rte_cryptodev_info_get(d->cdev_id, &d->cdev_info);
	if (d->cdev_info.max_nb_queue_pairs < d->nb_wk) {
		/* Fail closed rather than silently running fewer workers than
		 * requested: a clamped -n looks like scaling but is not. */
		fprintf(stderr, "r2dp-fwd: %s only has %u queue pairs but -n %u was "
		    "requested; add max_nb_queue_pairs=<n> to the --vdev (e.g. "
		    "--vdev='crypto_openssl0,max_nb_queue_pairs=%u')\n",
		    rte_cryptodev_name_get(d->cdev_id),
		    d->cdev_info.max_nb_queue_pairs, d->nb_wk, d->nb_wk);
		return -EINVAL;
	}
	memset(&cconf, 0, sizeof(cconf));
	cconf.socket_id = SOCKET_ID_ANY;
	cconf.nb_queue_pairs = (uint16_t)d->nb_wk;
	memset(&qconf, 0, sizeof(qconf));
	qconf.nb_descriptors = 2048;
	if (rte_cryptodev_configure(d->cdev_id, &cconf) < 0) {
		fprintf(stderr, "r2dp-fwd: cryptodev configure failed\n");
		return -EIO;
	}
	for (uint16_t q = 0; q < d->nb_wk; q++)
		if (rte_cryptodev_queue_pair_setup(d->cdev_id, q, &qconf,
		    SOCKET_ID_ANY) < 0) {
			fprintf(stderr, "r2dp-fwd: cryptodev qp %u setup failed\n", q);
			return -EIO;
		}
	if (rte_cryptodev_start(d->cdev_id) < 0) {
		fprintf(stderr, "r2dp-fwd: cryptodev start failed\n");
		return -EIO;
	}
	d->sess_mp = rte_cryptodev_sym_session_pool_create("r2dp_sess", DP_SESS_POOL,
	    rte_cryptodev_sym_get_private_session_size(d->cdev_id), 0, 0,
	    SOCKET_ID_ANY);
	/* each worker holds at most BURST_SZ ops in flight, plus whatever a
	 * stuck device still owns */
	d->cop_mp = rte_crypto_op_pool_create("r2dp_cop",
	    RTE_CRYPTO_OP_TYPE_SYMMETRIC, RTE_MAX(4096u,
	    4u * BURST_SZ * d->nb_wk), 0, sizeof(struct rte_crypto_op) +
	    sizeof(struct rte_crypto_sym_op) + R2DP_GCM_IV_LEN, SOCKET_ID_ANY);
	if (!d->sess_mp || !d->cop_mp) {
		fprintf(stderr, "r2dp-fwd: crypto mempools failed\n");
		return -ENOMEM;
	}
	d->have_cdev = 1;
	fprintf(stderr, "r2dp-fwd: crypto %s, %u queue pair(s)\n",
	    rte_cryptodev_name_get(d->cdev_id), d->nb_wk);
	return 0;
}

/* Dataplane ports, in EAL order: the first is the outer (ESP) side, the
 * second the inner (plaintext) side.  net_tap for the lab, net_memif and
 * net_vhost for VM / container wiring. */
static void
ports_find(struct dpdk_priv *d)
{
	static const char *const drv[] = { "tap", "memif", "vhost" };
	uint16_t port;

	d->port_id = -1;
	d->inner_port = -1;
	RTE_ETH_FOREACH_DEV(port) {
		struct rte_eth_dev_info di;
		int ok = 0;

		if (rte_eth_dev_info_get(port, &di) != 0)
			continue;
		for (size_t i = 0; i < RTE_DIM(drv); i++)
			ok |= strstr(di.driver_name, drv[i]) != NULL;
		if (!ok)
			continue;
		if (d->port_id < 0)
			d->port_id = port;
		else if (d->inner_port < 0)
			d->inner_port = port;
	}
}

static void
dpd_idle(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;

	spd_idle(d);
	if (__atomic_load_n(&d->n_zombie, __ATOMIC_RELAXED)) {
		rte_spinlock_lock(&d->lock);
		sa_reap(d);
		rte_spinlock_unlock(&d->lock);
	}
}

int
fwd_dp_dpdk_probe(struct fwd_dp *dp, int *argc, char **argv[],
    const char *sockpath, int verbose, int nb_workers, unsigned nh_size)
{
	struct dpdk_priv *d;
	unsigned maxw;
	int ret;

	(void)sockpath;
	if (nb_workers < 1 || nb_workers > DP_MAX_WK) {
		fprintf(stderr, "r2dp-fwd: -n %d: 1..%d workers\n", nb_workers,
		    DP_MAX_WK);
		return -EINVAL;
	}
	/* dpdk_priv is cache-line aligned (dp_wk is); calloc only
	 * guarantees natural (8-byte) alignment.  rte_zmalloc can't be used: the
	 * EAL heap does not exist yet.  aligned_alloc + memset (M3). */
	d = aligned_alloc(RTE_CACHE_LINE_SIZE, sizeof(*d));
	if (!d)
		return -ENOMEM;
	memset(d, 0, sizeof(*d));
	d->expire_fd = -1;
	d->verbose = verbose;
	d->nb_wk = (unsigned)nb_workers;
	if (nh_size > R2DP_NH_MAX_CAP) {
		fprintf(stderr, "r2dp-fwd: --nh-size %u: at most %u\n", nh_size,
		    R2DP_NH_MAX_CAP);
		free(d);
		return -EINVAL;
	}
	d->nh_size = nh_size;
	for (unsigned i = 0; i <= DP_MAX_WK; i++)
		dp_wk_init(d, i);
	snprintf(d->tap_if, sizeof(d->tap_if), "%s",
	    getenv("R2DP_TAP_IF") ? getenv("R2DP_TAP_IF") : TAP_IF_DEFAULT);

	ret = rte_eal_init(*argc, *argv);
	if (ret < 0) {
		/* rte_eal_init returns -1 and sets rte_errno.  -ENODEV is
		 * reserved for "no dataplane port" (main's control-only
		 * case), so an EAL failure never maps onto it. */
		ret = rte_errno > 0 && rte_errno != ENODEV ? -rte_errno : -EIO;
		fprintf(stderr, "r2dp-fwd: rte_eal_init failed: %s\n",
		    rte_strerror(-ret));
		free(d);
		return ret;
	}
	*argc -= ret;
	*argv += ret;

	d->pool = rte_pktmbuf_pool_create("r2dp_pool", MEMPOOL_SIZE, MEMPOOL_CACHE,
	    0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	if (!d->pool) {
		fprintf(stderr, "r2dp-fwd: mbuf pool failed: %s\n", rte_strerror(rte_errno));
		free(d);
		return -ENOMEM;
	}
	ret = crypto_init(d);
	/* -ENODEV: no crypto device -- tolerated, ESP is dropped and IKE still
	 * flows.  A device that is present but cannot be set up for -n
	 * workers refuses the dataplane instead (CRYPTOQ CQ2). */
	if (ret < 0 && ret != -ENODEV) {
		rte_mempool_free(d->pool);
		free(d);
		return ret;
	}

	{
		/* lock-free (SPI, DIP) table, grows by swap (dpdk_sad.c) */
		d->sad = dp_sad_create("r2dp_sad", DP_SAD_INIT);
		d->sad_cap = DP_SAD_INIT;
		if (!d->sad) {
			fprintf(stderr, "r2dp-fwd: sad create failed: %s\n",
			    rte_strerror(rte_errno));
			rte_mempool_free(d->pool);
			free(d);
			return -ENOMEM;
		}
	}
	rte_spinlock_init(&d->lock);

	ports_find(d);
	if (d->port_id < 0) {
		fprintf(stderr, "r2dp-fwd: no dataplane port found (add "
		    "--vdev=net_tap0,iface=r2dp-tap, or net_memif/net_vhost)\n");
		return -ENODEV;
	}
	/* Fix the worker count now, before any SA exists: it decides
	 * dp_sa.owner.  Clamp to the TX queues the ports offer. */
	maxw = max_workers(d);
	if (d->nb_wk > maxw) {
		fprintf(stderr, "r2dp-fwd: -n %u clamped to %u (port tx queues)\n",
		    d->nb_wk, maxw);
		d->nb_wk = maxw;
	}

	dp->priv = d;
	{
		int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (efd > 0) {
			d->expire_fd = efd;
			dp->wake_fd = efd;
		}
	}
	dpdk_ops.caps   = dpdk_caps;
	dpdk_ops.sa_add = dpd_sa_add;
	dpdk_ops.sa_bytes = dpd_sa_bytes;
	dpdk_ops.sa_set_hard_bytes = dpd_sa_set_hard_bytes;
	dpdk_ops.sa_set_hard_time = dpd_sa_set_hard_time;
	dpdk_ops.sp_add = dpd_sp_add;
	dpdk_ops.sp_del = dpd_sp_del;
	dpdk_ops.start  = dpd_start;
	dpdk_ops.stop   = dpd_stop;
	dpdk_ops.idle   = dpd_idle;
	dp->ops = &dpdk_ops;
	if (dp->ops->caps)
		dp->ops->caps(dp);
	ret = dp->ops->start(dp);   /* bring up the ports and workers */
	if (ret < 0) {
		fprintf(stderr, "r2dp-fwd: dataplane start failed: %s\n",
		    strerror(-ret));
		/* A failed start is not a running dataplane.  Drop the op table so
		 * ctl never applies SAs/SPs to a half-started/dead backend (and
		 * never reports a dataplane that cannot forward).  main treats
		 * this as DPDK-unavailable and serves control-only. */
		dp->ops = NULL;
		return ret;
	}
	fprintf(stderr, "r2dp-fwd: DPDK dataplane ready (port=%d inner=%d cdev=%d "
	    "workers=%u)\n", d->port_id, d->inner_port,
	    d->have_cdev ? d->cdev_id : -1, d->nb_wk);
	return 0;
}

#endif /* R2DP_HAVE_DPDK */

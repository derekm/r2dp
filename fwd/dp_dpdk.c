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

static struct fwd_dp_ops dpdk_ops;

/* ------------------------------------------------------------------ */
/* nq RX and nq TX queues (net_tap insists they match): one TX queue per
 * worker; with several workers the dispatcher polls every RX queue (a
 * multiqueue tap spreads the kernel's frames over all of them). */
static int
port_init(struct dpdk_priv *d, uint16_t port, unsigned ntxq)
{
	struct rte_eth_conf conf;
	struct rte_eth_dev_info dev_info;

	if (port >= RTE_MAX_ETHPORTS)
		return -1;
	memset(&conf, 0, sizeof(conf));
	if (rte_eth_dev_info_get(port, &dev_info) < 0) {
		fprintf(stderr, "r2dp-fwd: dev_info_get(port %u) failed\n", port);
		return -1;
	}
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	uint16_t nrxq = (uint16_t)ntxq;
	if (ntxq > dev_info.max_tx_queues) {
		fprintf(stderr, "r2dp-fwd: port %u has %u tx queues, need %u\n",
		    port, dev_info.max_tx_queues, ntxq);
		return -1;
	}
	if (rte_eth_dev_configure(port, nrxq, (uint16_t)ntxq, &conf) < 0)
		return -rte_errno;
	for (uint16_t q = 0; q < nrxq; q++)
		if (rte_eth_rx_queue_setup(port, q, 1024, rte_eth_dev_socket_id(port),
		    NULL, d->pool) < 0)
			return -rte_errno;
	for (uint16_t q = 0; q < (uint16_t)ntxq; q++)
		if (rte_eth_tx_queue_setup(port, q, 1024, rte_eth_dev_socket_id(port),
		    NULL) < 0)
			return -rte_errno;
	if (rte_eth_dev_start(port) < 0)
		return -rte_errno;
	rte_eth_promiscuous_enable(port);
	return 0;
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

/* Learn the peer's MAC (keyed by its IP) only from unicast IKE/ESP whose
 * source is a configured tunnel peer, so an arbitrary host on the segment
 * cannot capture egress ESP; relearn when the peer's MAC changes (N1).
 * Called only by the lcore that receives on the outer port (the single
 * writer of d->nh). */
/* Per-burst memo: a burst is mostly one peer, and a repeat of the
 * previous frame's (source IP, source MAC) at the same `now` would change
 * nothing -- skip its peer check and table scan. */
struct nh_memo {
	uint64_t now;
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
	lr = r2dp_nh_learn(&d->nh, sip, smac, mo->now);
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
	struct nh_memo mo = { .now = learn ? rte_get_tsc_cycles() : 0 };
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
			uint16_t sent = rte_eth_tx_burst(to, w->txq, txq, ntx);
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
		for (uint16_t i = 0; i < nex; i++) {
			if (is_ike_arp(exc[i]))
				fwd[nf++] = exc[i];
			else
				DROP(w, DR_CLEAR_OUTER, 1);
		}
		if (nf) {
			if (is_udp(fwd[0]))
				w->n_ike += nf;   /* IKE */
			uint16_t sent = rte_eth_tx_burst(to, w->txq, fwd, nf);
			w->n_tx += sent;
			DROP(w, DR_TX_FULL, nf - sent);
			for (uint16_t i = sent; i < nf; i++)
				rte_pktmbuf_free(fwd[i]);
		}
		/* dropped-exception mbufs are freed here */
		for (uint16_t i = 0; i < nex; i++)
			if (!is_ike_arp(exc[i]))
				rte_pktmbuf_free(exc[i]);
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
		uint32_t last_dst = 0;          /* per-burst next-hop memo */
		uint8_t nmac[6];
		int have = 0;
		for (uint16_t i = 0; i < nout; i++) {
			struct rte_ether_hdr *eh;
			char *h = rte_pktmbuf_prepend(esp_out[i], RTE_ETHER_HDR_LEN);
			if (!h) { DROP(w, DR_NOMEM, 1); rte_pktmbuf_free(esp_out[i]); continue; }
			eh = rte_pktmbuf_mtod(esp_out[i], struct rte_ether_hdr *);
			/* Egress ESP is unicast to the tunnel peer's learned
			 * next hop (keyed by the outer destination IP).  With
			 * no learned MAC, drop: broadcasting ESP would spray it
			 * to every host on the segment (N2). */
			{
				const struct rte_ipv4_hdr *oip =
				    (const struct rte_ipv4_hdr *)(eh + 1);
				uint32_t odst;
				memcpy(&odst, &oip->dst_addr, 4);
				if (!have || odst != last_dst) {
					have = r2dp_nh_lookup(&d->nh, odst, nmac);
					last_dst = odst;
				}
				if (!have) {
					DROP(w, DR_NO_NEXTHOP, 1);
					rte_pktmbuf_free(esp_out[i]);
					continue;
				}
				memcpy(eh->dst_addr.addr_bytes, nmac, 6);
				memcpy(eh->src_addr.addr_bytes, d->our_mac, 6);
			}
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
		uint16_t sent = rte_eth_tx_burst(to, w->txq, txq, ntx);
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
		if (ntx && is_udp(txq[0]))
			w->n_ike += ntx;
		uint16_t sent = rte_eth_tx_burst(to, w->txq, txq, ntx);
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

/* Packet worker.  With one worker it polls queue 0 of both ports itself
 * (run to completion, as before multi-worker support).  With several, the
 * dispatcher (below) feeds it through two SP/SC rings and it only ever
 * handles packets for SAs it owns (dp_sa.owner), so every per-SA piece of
 * mutable state -- the replay window, the outbound sequence number -- has
 * exactly one writer. */
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
			nr = rte_ring_sc_dequeue_burst(w->ring_o, (void **)bufs,
			    BURST_SZ, NULL);
			if (nr)
				outer_burst(w, bufs, nr, port, 0);
			nr = rte_ring_sc_dequeue_burst(w->ring_i, (void **)bufs,
			    BURST_SZ, NULL);
			if (nr)
				inner_burst(w, bufs, nr,
				    d->inner_port >= 0 ? d->inner_port : port);
		}
		/* quiescent: ctl may now free anything read this iteration */
		if (d->rcu)
			rte_rcu_qsbr_quiescent(d->rcu, w->lcore);
		if (single)
			housekeeping(d, &last_t);
	}
	qsbr_offline(d, w->lcore);
	return 0;
}

/* Worker owning the inbound SA an outer frame is for: ESP or ESP-in-UDP is
 * looked up in the SAD by (SPI, outer dst); everything else (IKE, ARP,
 * clear, SAD misses) goes to worker 0, which forwards or drops it exactly
 * as a single worker would. */
static unsigned
steer_outer(struct dpdk_priv *d, struct rte_mbuf *m)
{
	const uint8_t *p = rte_pktmbuf_mtod(m, const uint8_t *);
	uint32_t len = rte_pktmbuf_data_len(m), off, spi;
	const struct rte_ipv4_hdr *ip;
	union rte_ipsec_sad_key k;
	const union rte_ipsec_sad_key *kp = &k;
	void *sa = NULL;
	const struct dp_sa *ds;

	if (len < RTE_ETHER_HDR_LEN + sizeof(*ip) || p[12] != 0x08 || p[13] != 0)
		return 0;
	ip = (const struct rte_ipv4_hdr *)(p + RTE_ETHER_HDR_LEN);
	if ((ip->version_ihl >> 4) != 4)
		return 0;
	off = RTE_ETHER_HDR_LEN + (ip->version_ihl & 0x0f) * 4u;
	if (ip->next_proto_id == IPPROTO_UDP) {
		if (natt_class(p, len) != NT_ESP)
			return 0;
		off += 8;
	} else if (ip->next_proto_id != IPPROTO_ESP) {
		return 0;
	}
	if (len < off + 4)
		return 0;
	memcpy(&spi, p + off, 4);
	memset(&k, 0, sizeof(k));
	k.v4.spi = ntohl(spi);
	k.v4.dip = ip->dst_addr;
	if (rte_ipsec_sad_lookup(d->sad, &kp, &sa, 1) != 1 || !sa)
		return 0;
	ds = sa_of_sess(d, sa);
	return ds ? ds->owner % d->nb_wk : 0;
}

/* Worker for an inner (plaintext) frame: the owner of the egress SA its
 * OUT PROTECT policy is bound to; anything else (bypass, discard, no SA,
 * non-IPv4) by a hash of the addresses, so a flow stays in order. */
static unsigned
steer_inner(struct dpdk_priv *d, struct rte_mbuf *m)
{
	const uint8_t *p = rte_pktmbuf_mtod(m, const uint8_t *);
	uint32_t len = rte_pktmbuf_data_len(m);
	const struct rte_ipv4_hdr *ip;
	const struct r2dp_sp *sp;
	struct dp_sa *ds;

	if (len < RTE_ETHER_HDR_LEN + sizeof(*ip))
		return 0;
	ip = (const struct rte_ipv4_hdr *)(p + RTE_ETHER_HDR_LEN);
	if ((ip->version_ihl >> 4) != 4)
		return 0;
	sp = sp_match_out(d, ip, len - RTE_ETHER_HDR_LEN, &ds);
	if (sp && ds && sp->action == R2DP_ACT_PROTECT)
		return ds->owner % d->nb_wk;
	return rte_hash_crc_4byte(ip->dst_addr,
	    rte_hash_crc_4byte(ip->src_addr, 0)) % d->nb_wk;
}

/* Hand per-worker batches to their rings; what does not fit is dropped
 * and counted on the dispatcher (DR_STEER). */
static void
dispatch_flush(struct dp_wk *dw, struct rte_mbuf *q[][BURST_SZ],
    uint16_t *nq, int outer)
{
	struct dpdk_priv *d = dw->d;

	for (unsigned i = 0; i < d->nb_wk; i++) {
		struct rte_ring *r = outer ? d->wk[i].ring_o : d->wk[i].ring_i;
		unsigned sent;

		if (!nq[i])
			continue;
		sent = rte_ring_sp_enqueue_burst(r, (void **)q[i], nq[i], NULL);
		if (sent < nq[i]) {
			DROP(dw, DR_STEER, nq[i] - sent);
			rte_pktmbuf_free_bulk(&q[i][sent], nq[i] - sent);
		}
		nq[i] = 0;
	}
}

/* Multi-worker dispatcher: the only lcore that receives.  It learns next
 * hops and consumes NAT keepalives (so d->nh has one writer), then steers
 * each frame to the worker that owns its SA.  It reads the SAD and the
 * policy snapshot, so it is a QSBR reader like the workers. */
static int
dispatcher_main(void *arg)
{
	struct dp_wk *dw = arg;
	struct dpdk_priv *d = dw->d;
	struct rte_mbuf *bufs[BURST_SZ];
	struct rte_mbuf *q[DP_MAX_WK][BURST_SZ];
	uint16_t nq[DP_MAX_WK] = { 0 };
	uint64_t last_t = 0;
	unsigned qi = 0;

	fprintf(stderr, "r2dp-fwd: dispatcher on lcore %u for %u workers\n",
	    rte_lcore_id(), d->nb_wk);
	qsbr_online(d, dw->lcore);
	while (__atomic_load_n(&d->running, __ATOMIC_RELAXED)) {
		uint16_t rq = qi++ % d->nb_wk;     /* round-robin the RX queues */
		uint16_t nr = rte_eth_rx_burst(d->port_id, rq, bufs, BURST_SZ);

		struct nh_memo mo = { .now = nr ? rte_get_tsc_cycles() : 0 };

		dw->n_rx += nr;
		for (uint16_t i = 0; i < nr; i++) {
			unsigned t;

			nh_learn_frame(d, bufs[i], &mo);
			if (natt_class(rte_pktmbuf_mtod(bufs[i], const uint8_t *),
			    rte_pktmbuf_data_len(bufs[i])) == NT_KEEPALIVE) {
				dw->n_natt_keepalive++;   /* RFC 3948 s2.3 */
				rte_pktmbuf_free(bufs[i]);
				continue;
			}
			t = steer_outer(d, bufs[i]);
			q[t][nq[t]++] = bufs[i];
		}
		dispatch_flush(dw, q, nq, 1);
		if (d->inner_port >= 0) {
			nr = rte_eth_rx_burst(d->inner_port, rq, bufs, BURST_SZ);
			dw->n_rx += nr;
			for (uint16_t i = 0; i < nr; i++) {
				unsigned t = steer_inner(d, bufs[i]);
				q[t][nq[t]++] = bufs[i];
			}
			dispatch_flush(dw, q, nq, 0);
		}
		if (d->rcu)
			rte_rcu_qsbr_quiescent(d->rcu, dw->lcore);
		housekeeping(d, &last_t);
	}
	qsbr_offline(d, dw->lcore);
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

/* Launch nb_wk workers (plus a dispatcher when nb_wk > 1) on the EAL
 * worker lcores.  nb_wk was fixed at probe time, before any SA could be
 * installed, because it decides dp_sa.owner. */
static int
dpd_start(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;
	unsigned lc[DP_MAX_WK + 1], nlc = 0, need, lcore;

	if (d->port_id < 0)
		return -ENODEV;
	if (d->running)
		return -EBUSY;
	need = d->nb_wk + (d->nb_wk > 1);
	RTE_LCORE_FOREACH_WORKER(lcore) {
		if (nlc == need)
			break;
		lc[nlc++] = lcore;
	}
	if (nlc < need) {
		fprintf(stderr, "r2dp-fwd: %u worker(s) need %u spare lcores, "
		    "have %u (e.g. -l 0-%u)\n", d->nb_wk, need, nlc, need);
		return -EAGAIN;
	}
	if (port_init(d, d->port_id, d->nb_wk) < 0)
		return -rte_errno;
	/* inner (plaintext) tap is optional: single-tap mode (interop lab,
	 * control-only) has only the outer port */
	if (d->inner_port >= 0 && port_init(d, d->inner_port, d->nb_wk) < 0) {
		fprintf(stderr, "r2dp-fwd: inner port init failed\n");
		d->inner_port = -1;
	}
	/* H5: QSBR so the ctl (main) thread can free SA/SP memory only after
	 * every reader has passed a grace period -- the workers read
	 * sa_tab/sp_tab and hold session pointers across their crypto path
	 * with no lock.  tid = lcore id (< RTE_MAX_LCORE). */
	{
		size_t rsz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
		d->rcu = rte_zmalloc("r2dp-rcu", rsz, RTE_CACHE_LINE_SIZE);
		if (!d->rcu) {
			fprintf(stderr, "r2dp-fwd: rte_rcu_qsbr alloc failed\n");
			return -ENOMEM;
		}
		rte_rcu_qsbr_init(d->rcu, RTE_MAX_LCORE);
	}
	for (unsigned i = 0; i <= d->nb_wk; i++) {
		dp_wk_init(d, i);
		if (i < need)
			d->wk[i].lcore = lc[i];
	}
	if (d->nb_wk > 1)
		for (unsigned i = 0; i < d->nb_wk; i++) {
			char n[RTE_RING_NAMESIZE];
			snprintf(n, sizeof(n), "r2dp_ro%u", i);
			d->wk[i].ring_o = rte_ring_create(n, DP_RING_SZ,
			    SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
			snprintf(n, sizeof(n), "r2dp_ri%u", i);
			d->wk[i].ring_i = rte_ring_create(n, DP_RING_SZ,
			    SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (!d->wk[i].ring_o || !d->wk[i].ring_i) {
				fprintf(stderr, "r2dp-fwd: worker ring: %s\n",
				    rte_strerror(rte_errno));
				return -ENOMEM;
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
	if (d->nb_wk > 1)
		rte_eal_remote_launch(dispatcher_main, &d->wk[d->nb_wk],
		    d->wk[d->nb_wk].lcore);
	return 0;
}

static void
dpd_stop(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;

	__atomic_store_n(&d->running, 0, __ATOMIC_RELAXED);
	for (unsigned i = 0; i <= d->nb_wk; i++) {
		struct dp_wk *w = &d->wk[i];
		struct rte_mbuf *m;

		if (w->lcore < RTE_MAX_LCORE) {
			rte_eal_wait_lcore(w->lcore);
			if (d->rcu)
				rte_rcu_qsbr_thread_unregister(d->rcu, w->lcore);
		}
		while (w->ring_o && rte_ring_dequeue(w->ring_o, (void **)&m) == 0)
			rte_pktmbuf_free(m);
		while (w->ring_i && rte_ring_dequeue(w->ring_i, (void **)&m) == 0)
			rte_pktmbuf_free(m);
		rte_ring_free(w->ring_o);
		rte_ring_free(w->ring_i);
		w->ring_o = w->ring_i = NULL;
	}
	if (d->rcu) {
		rte_free(d->rcu);
		d->rcu = NULL;
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
		fprintf(stderr, "r2dp-fwd: %s has %u queue pairs; -n %u clamped\n",
		    rte_cryptodev_name_get(d->cdev_id),
		    d->cdev_info.max_nb_queue_pairs, d->nb_wk);
		d->nb_wk = RTE_MAX(1u, d->cdev_info.max_nb_queue_pairs);
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
	d->sess_mp = rte_cryptodev_sym_session_pool_create("r2dp_sess", MAX_SA,
	    rte_cryptodev_sym_get_private_session_size(d->cdev_id), 0, 0,
	    SOCKET_ID_ANY);
	/* each worker holds at most BURST_SZ ops in flight, plus whatever a
	 * stuck device still owns */
	d->cop_mp = rte_crypto_op_pool_create("r2dp_cop",
	    RTE_CRYPTO_OP_TYPE_SYMMETRIC, RTE_MAX((unsigned)MAX_SA,
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

int
fwd_dp_dpdk_probe(struct fwd_dp *dp, int *argc, char **argv[],
    const char *sockpath, int verbose, int nb_workers)
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
	/* sa_tab[] holds struct rte_ipsec_session (64-byte aligned); calloc only
	 * guarantees natural (8-byte) alignment.  rte_zmalloc can't be used: the
	 * EAL heap does not exist yet.  aligned_alloc + memset (M3). */
	d = aligned_alloc(RTE_CACHE_LINE_SIZE, sizeof(*d));
	if (!d)
		return -ENOMEM;
	memset(d, 0, sizeof(*d));
	d->verbose = verbose;
	d->nb_wk = (unsigned)nb_workers;
	for (unsigned i = 0; i <= DP_MAX_WK; i++)
		dp_wk_init(d, i);
	snprintf(d->tap_if, sizeof(d->tap_if), "%s",
	    getenv("R2DP_TAP_IF") ? getenv("R2DP_TAP_IF") : TAP_IF_DEFAULT);

	ret = rte_eal_init(*argc, *argv);
	if (ret < 0) {
		fprintf(stderr, "r2dp-fwd: rte_eal_init failed (%d)\n", ret);
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
	(void)crypto_init(d);      /* none: ESP is dropped, IKE still flows */

	{
		struct rte_ipsec_sad_conf conf;

		memset(&conf, 0, sizeof(conf));
		conf.socket_id = SOCKET_ID_ANY;
		/* Only the SPI_DIP key flavor is used (inbound ESP lookup).  Leave
		 * the other table types unsized (0) so the SAD doesn't preallocate
		 * SPI_ONLY / SPI_DIP_SIP tables we never query. */
		conf.max_sa[RTE_IPSEC_SAD_SPI_DIP] = MAX_SA;
		conf.flags = RTE_IPSEC_SAD_FLAG_RW_CONCURRENCY;
		d->sad = rte_ipsec_sad_create("r2dp_sad", &conf);
		if (!d->sad) {
			fprintf(stderr, "r2dp-fwd: sad create failed: %s\n",
			    rte_strerror(rte_errno));
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
	dpdk_ops.caps   = dpdk_caps;
	dpdk_ops.sa_add = dpd_sa_add;
	dpdk_ops.sa_bytes = dpd_sa_bytes;
	dpdk_ops.sp_add = dpd_sp_add;
	dpdk_ops.sp_del = dpd_sp_del;
	dpdk_ops.start  = dpd_start;
	dpdk_ops.stop   = dpd_stop;
	dp->ops = &dpdk_ops;
	if (dp->ops->caps)
		dp->ops->caps(dp);
	ret = dp->ops->start(dp);   /* bring up the ports and workers */
	if (ret < 0)
		fprintf(stderr, "r2dp-fwd: dataplane start failed: %s\n",
		    strerror(-ret));
	fprintf(stderr, "r2dp-fwd: DPDK dataplane %s (port=%d inner=%d cdev=%d "
	    "workers=%u)\n", ret < 0 ? "NOT running" : "ready", d->port_id,
	    d->inner_port, d->have_cdev ? d->cdev_id : -1, d->nb_wk);
	return 0;
}

#endif /* R2DP_HAVE_DPDK */

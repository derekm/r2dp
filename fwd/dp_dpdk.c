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
/* M1 packet path: run-to-completion on one lcore.  rx from the tap port,
 * classify, and tx back (the M1 topology is a TAP bridged to a kernel
 * interface; ESP is later processed, non-ESP IKE/ARP rides the exception
 * path -- both re-emit on the same port so the kernel sees them). */
static int
port_init(struct dpdk_priv *d, uint16_t port)
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

	uint16_t nrxq = NB_RX_QUEUE, ntxq = NB_TX_QUEUE;
	if (rte_eth_dev_configure(port, nrxq, ntxq, &conf) < 0)
		return -rte_errno;
	for (uint16_t q = 0; q < nrxq; q++)
		if (rte_eth_rx_queue_setup(port, q, 1024, rte_eth_dev_socket_id(port),
		    NULL, d->pool) < 0)
			return -rte_errno;
	for (uint16_t q = 0; q < ntxq; q++)
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
worker_outer(struct dpdk_priv *d, int port)
{
	struct rte_mbuf *bufs[BURST_SZ];
	struct rte_mbuf *esp[BURST_SZ], *exc[BURST_SZ];
	uint16_t nr = rte_eth_rx_burst(port, 0, bufs, BURST_SZ);

	if (nr == 0)
		return;
	d->n_rx += nr;
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
	for (uint16_t i = 0; i < nr; i++) {
		/* Learn the peer's MAC (keyed by its IP) only from unicast
		 * IKE/ESP whose source is a configured tunnel peer, so an
		 * arbitrary host on the segment cannot capture egress ESP;
		 * relearn when the peer's MAC changes (N1). */
		{
			uint32_t sip;
			const uint8_t *smac;
			if (r2dp_nh_frame_ike_esp(rte_pktmbuf_mtod(bufs[i],
			    const uint8_t *), rte_pktmbuf_data_len(bufs[i]),
			    &sip, &smac) && is_tunnel_peer(d, sip)) {
				int lr = r2dp_nh_learn(&d->nh, sip, smac,
				    rte_get_tsc_cycles());
				if (lr > 0 && d->verbose)
					fprintf(stderr, "r2dp-fwd: %s next hop for "
					    "peer %08x: %02x:%02x:%02x:%02x:%02x:%02x\n",
					    lr == 2 ? "relearned" : "learned", sip,
					    smac[0], smac[1], smac[2], smac[3],
					    smac[4], smac[5]);
			}
		}
		if (natt_class(rte_pktmbuf_mtod(bufs[i], const uint8_t *),
		    rte_pktmbuf_data_len(bufs[i])) == NT_KEEPALIVE) {
			d->n_natt_keepalive++;      /* RFC 3948 s2.3: discard */
			rte_pktmbuf_free(bufs[i]);
			continue;
		}
		if (is_esp(bufs[i]) || is_nat_esp(bufs[i])) {
			d->n_esp++;
			esp[nesp++] = bufs[i];
		} else {
			exc[nex++] = bufs[i];
		}
	}

	if (nesp) {
		struct rte_mbuf *dec[BURST_SZ];
		uint16_t ndec = 0;
		esp_inbound(d, esp, nesp, dec, &ndec);
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
					DROP(d, DR_NOMEM, 1);
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
			uint16_t sent = rte_eth_tx_burst(to, 0, txq, ntx);
			d->n_tx += sent;
			DROP(d, DR_TX_FULL, ntx - sent);
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
				DROP(d, DR_CLEAR_OUTER, 1);
		}
		if (nf) {
			if (is_udp(fwd[0]))
				d->n_ike += nf;   /* IKE */
			uint16_t sent = rte_eth_tx_burst(to, 0, fwd, nf);
			d->n_tx += sent;
			DROP(d, DR_TX_FULL, nf - sent);
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
worker_inner(struct dpdk_priv *d, int port)
{
	struct rte_mbuf *bufs[BURST_SZ];
	uint16_t nr = rte_eth_rx_burst(port, 0, bufs, BURST_SZ);

	if (nr == 0)
		return;
	d->n_rx += nr;

	/* 1. classify: ESP here is anomalous -> drop; non-ESP may be protected
	 *    (encrypt) or unprotected (IKE/ARP -> exception path). */
	struct rte_mbuf *nonesp[BURST_SZ];
	uint16_t nnon = 0;
	for (uint16_t i = 0; i < nr; i++) {
		if (is_esp(bufs[i])) {
			DROP(d, DR_ESP_ON_INNER, 1);
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
	esp_outbound(d, nonesp, nnon, esp_out, &nout, &nby);

	/* 3. prepend L2 to the ESP datagrams and tx to the outer (peer) tap */
	if (nout) {
		uint16_t ntx = 0;
		struct rte_mbuf *txq[BURST_SZ];
		uint16_t to = (d->port_id >= 0) ? d->port_id : port;
		for (uint16_t i = 0; i < nout; i++) {
			struct rte_ether_hdr *eh;
			char *h = rte_pktmbuf_prepend(esp_out[i], RTE_ETHER_HDR_LEN);
			if (!h) { DROP(d, DR_NOMEM, 1); rte_pktmbuf_free(esp_out[i]); continue; }
			eh = rte_pktmbuf_mtod(esp_out[i], struct rte_ether_hdr *);
			/* Egress ESP is unicast to the tunnel peer's learned
			 * next hop (keyed by the outer destination IP).  With
			 * no learned MAC, drop: broadcasting ESP would spray it
			 * to every host on the segment (N2). */
			{
				const struct rte_ipv4_hdr *oip =
				    (const struct rte_ipv4_hdr *)(eh + 1);
				uint32_t odst;
				uint8_t nmac[6];
				memcpy(&odst, &oip->dst_addr, 4);
				if (!r2dp_nh_lookup(&d->nh, odst, nmac)) {
					DROP(d, DR_NO_NEXTHOP, 1);
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
		uint16_t sent = rte_eth_tx_burst(to, 0, txq, ntx);
		d->n_tx += sent;
		DROP(d, DR_TX_FULL, ntx - sent);
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
			d->n_ike += ntx;
		uint16_t sent = rte_eth_tx_burst(to, 0, txq, ntx);
		d->n_tx += sent;
		DROP(d, DR_TX_FULL, ntx - sent);
		for (uint16_t i = sent; i < ntx; i++)
			rte_pktmbuf_free(txq[i]);
	}
}

/* Weak so test programs that #include this file without dp.c link; the
 * forwarder's strong definition lives in dp.c. */
__attribute__((weak)) volatile sig_atomic_t fwd_stats_req;

static int
worker_main(void *arg)
{
	struct dpdk_priv *d = arg;
	uint16_t port = d->port_id;
	uint64_t last_t = 0;

	fprintf(stderr, "r2dp-fwd: worker on lcore %u, outer=%u inner=%d\n",
	    rte_lcore_id(), port, d->inner_port);
	/* H5: register this worker as a QSBR reader so ctl can synchronize
	 * before freeing SA/SP memory.  tid = its lcore id (< RTE_MAX_LCORE). */
	{
		struct rte_ether_addr ea;
		if (rte_eth_macaddr_get(port, &ea) == 0)
			memcpy(d->our_mac, ea.addr_bytes, 6);
		if (d->inner_port >= 0 &&
		    rte_eth_macaddr_get(d->inner_port, &ea) == 0)
			memcpy(d->our_inner_mac, ea.addr_bytes, 6);
	}
	if (d->rcu) {
		rte_rcu_qsbr_thread_register(d->rcu, d->worker_lcore);
		rte_rcu_qsbr_thread_online(d->rcu, d->worker_lcore);
	}
	while (d->running) {
		uint64_t now = rte_rdtsc();

		worker_outer(d, port);
		if (d->inner_port >= 0)
			worker_inner(d, d->inner_port);

		/* report quiescent: ctl may now free anything read this iteration */
		if (d->rcu)
			rte_rcu_qsbr_quiescent(d->rcu, d->worker_lcore);

		if (fwd_stats_req) {
			fwd_stats_req = 0;
			dpd_stats_dump(d, stderr);
		}
		if (!last_t)
			last_t = now;
		else if (now - last_t >= rte_get_timer_hz()) {  /* ~1s */
			fprintf(stderr,
			    "r2dp-fwd: stats rx=%llu tx=%llu esp=%llu ike=%llu drop=%llu\n",
			    (unsigned long long)d->n_rx,
			    (unsigned long long)d->n_tx,
			    (unsigned long long)d->n_esp,
			    (unsigned long long)d->n_ike,
			    (unsigned long long)d->n_drop);
			last_t = now;
		}
	}
	if (d->rcu)
		rte_rcu_qsbr_thread_offline(d->rcu, d->worker_lcore);
	return 0;
}

/* Exactly one worker owns the packet path.  Its per-SA state -- the
 * anti-replay window (rp_top/rp_map), byte counters, cq_stale and the drop
 * counters -- is written without locks or atomics.  Running a second
 * worker needs per-core SAs (RSS by SPI) or a per-SA lock first; until
 * then dpd_start launches one and refuses a second start. */
#define DP_NB_WORKERS 1
_Static_assert(DP_NB_WORKERS == 1,
    "replay window and SA counters are single-writer worker state");

static int
dpd_start(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;
	unsigned lcore;

	if (d->port_id < 0)
		return -ENODEV;
	if (d->running)
		return -EBUSY;        /* one worker only (DP_NB_WORKERS) */
	/* pick a slave lcore, skipping the main (calling) lcore */
	lcore = rte_get_next_lcore(-1, 1, 1);
	if (lcore >= RTE_MAX_LCORE) {
		fprintf(stderr, "r2dp-fwd: no spare lcore for the worker "
		    "(run with -l 0,<n>, e.g. -l 0-1)\n");
		return -EAGAIN;
	}
	if (port_init(d, d->port_id) < 0)
		return -rte_errno;
	/* inner (plaintext) tap is optional: single-tap mode (interop lab,
	 * control-only) has only the outer port */
	if (d->inner_port >= 0)
		if (port_init(d, d->inner_port) < 0)
			fprintf(stderr, "r2dp-fwd: inner tap init failed\n");
	/* H5: QSBR so the ctl (main) thread can free SA/SP memory only after the
	 * worker has passed a grace period -- the worker reads sa_tab/sp_tab and
	 * holds session pointers across its crypto path with no lock, so a
	 * synchronize here prevents a UAF when ctl deletes/rekeys under load.
	 * This DPDK has no rte_rcu_qsbr_alloc: size it, then rte_zmalloc. */
	{
		size_t rsz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
		d->rcu = rte_zmalloc("r2dp-rcu", rsz, RTE_CACHE_LINE_SIZE);
		if (!d->rcu) {
			fprintf(stderr, "r2dp-fwd: rte_rcu_qsbr alloc failed\n");
			return -ENOMEM;
		}
		rte_rcu_qsbr_init(d->rcu, RTE_MAX_LCORE);
	}
	if (rte_lcore_count() > 1 + DP_NB_WORKERS)
		fprintf(stderr, "r2dp-fwd: %u lcores given, using one worker "
		    "(replay state is single-writer); the rest stay idle\n",
		    rte_lcore_count());
	d->running = 1;
	d->worker_lcore = lcore;
	rte_eal_remote_launch(worker_main, d, lcore);
	return 0;
}

static void
dpd_stop(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;

	d->running = 0;
	if (d->worker_lcore < RTE_MAX_LCORE)
		rte_eal_wait_lcore(d->worker_lcore);
	if (d->rcu) {
		rte_rcu_qsbr_thread_unregister(d->rcu, d->worker_lcore);
		rte_free(d->rcu);
		d->rcu = NULL;
	}
	spd_teardown(d);
}

/* ------------------------------------------------------------------ */
int
fwd_dp_dpdk_probe(struct fwd_dp *dp, int *argc, char **argv[],
    const char *sockpath, int verbose)
{
	struct dpdk_priv *d;
	uint16_t port;
	int ret;

	(void)sockpath;
	/* sa_tab[] holds struct rte_ipsec_session (64-byte aligned); calloc only
	 * guarantees natural (8-byte) alignment, which is UB (UBSan flags it in
	 * gcm_kat too).  rte_zmalloc can't be used here: this struct is allocated
	 * BEFORE rte_eal_init (no DPDK heap yet, so rte_zmalloc fails with
	 * ENOMEM and the dataplane is silently lost).  aligned_alloc from the C
	 * library gives the required alignment without the EAL heap (M3). */
	d = aligned_alloc(RTE_CACHE_LINE_SIZE, sizeof(*d));
	if (!d)
		return -ENOMEM;
	d->verbose = verbose;
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

	ret = rte_cryptodev_get_dev_id("crypto_openssl0");
	if (ret < 0)
		ret = rte_cryptodev_get_dev_id("crypto_openssl");
	if (ret >= 0) {
		d->cdev_id = (uint8_t)ret;
		rte_cryptodev_info_get(d->cdev_id, &d->cdev_info);
		d->have_cdev = 1;
		/* configure + start the crypto device with one qp */
		struct rte_cryptodev_config cconf;
		struct rte_cryptodev_qp_conf qconf;
		memset(&cconf, 0, sizeof(cconf));
		cconf.socket_id = SOCKET_ID_ANY;
		cconf.nb_queue_pairs = 1;
		cconf.ff_disable = 0;
		if (rte_cryptodev_configure(d->cdev_id, &cconf) < 0) {
			fprintf(stderr, "r2dp-fwd: cryptodev configure failed\n");
			d->have_cdev = 0;
		} else {
			memset(&qconf, 0, sizeof(qconf));
			qconf.nb_descriptors = 2048;
			if (rte_cryptodev_queue_pair_setup(d->cdev_id, 0, &qconf,
			    SOCKET_ID_ANY) < 0)
				fprintf(stderr, "r2dp-fwd: cryptodev qp setup failed\n");
			else if (rte_cryptodev_start(d->cdev_id) < 0)
				fprintf(stderr, "r2dp-fwd: cryptodev start failed\n");
		}
		if (d->have_cdev) {
			/* crypto session + op mempools */
			d->sess_mp = rte_cryptodev_sym_session_pool_create(
			    "r2dp_sess", MAX_SA,
			    rte_cryptodev_sym_get_private_session_size(d->cdev_id),
			    0, 0, SOCKET_ID_ANY);
			if (!d->sess_mp)
				fprintf(stderr, "r2dp-fwd: sess pool failed\n");
			d->cop_mp = rte_crypto_op_pool_create(
			    "r2dp_cop", RTE_CRYPTO_OP_TYPE_SYMMETRIC, MAX_SA, 0,
			    sizeof(struct rte_crypto_op) +
			      sizeof(struct rte_crypto_sym_op) +
			      R2DP_GCM_IV_LEN,
			    SOCKET_ID_ANY);
			if (!d->cop_mp)
				fprintf(stderr, "r2dp-fwd: crypto-op pool failed\n");
		}
	} else {
		fprintf(stderr, "r2dp-fwd: warning: no crypto device; add "
		    "--vdev crypto_openssl0 for AES-GCM\n");
	}

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

	d->port_id = -1;
	d->inner_port = -1;
	RTE_ETH_FOREACH_DEV(port) {
		struct rte_eth_dev_info di;
		if (rte_eth_dev_info_get(port, &di) == 0 &&
		    strstr(di.driver_name, "tap")) {
			if (d->port_id < 0) {
				d->port_id = port;                /* outer = ESP side */
			} else if (d->inner_port < 0) {
				d->inner_port = port;             /* inner = plaintext side */
			}
		}
	}
	if (d->port_id < 0) {
		fprintf(stderr, "r2dp-fwd: no tap port found "
		    "(add --vdev=net_tap0,iface=r2dp-tap)\n");
		return -ENODEV;
	}

	dp->priv = d;
	/* wire the vtable: caps/sa/sp plus the worker start/stop */
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
	if (dp->ops->start)
		dp->ops->start(dp);   /* bring up the worker + port */
	fprintf(stderr, "r2dp-fwd: DPDK dataplane ready (port=%d cdev=%d sad=%p)\n",
	    d->port_id, d->cdev_id, (void *)d->sad);
	return 0;
}

#endif /* R2DP_HAVE_DPDK */

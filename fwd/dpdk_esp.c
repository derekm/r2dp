/*
 * fwd/dpdk_esp.c -- DPDK data plane: ESP packet processing.
 * 
 * Inbound (SAD lookup, NAT-T demux, crypto, our anti-replay window, inner
 * selector check) and outbound (policy match, crypto, NAT-T encapsulation)
 * through librte_ipsec on a lookaside cryptodev, batched per SA.
 */
#ifdef R2DP_HAVE_DPDK

#include "dpdk_int.h"


/* RFC 3948 s2.2 demux of what arrives on UDP/4500, for an Ethernet frame:
 *  - 0xFF, the only payload byte          -> NAT keepalive (consumed);
 *  - four zero bytes (non-ESP marker)     -> IKE (exception path);
 *  - anything else: a non-zero SPI field  -> ESP-in-UDP, ESP right after
 *    the 8-byte UDP header (no marker).
 * Bounds are checked against `len` (the first segment). */
int
natt_class(const uint8_t *p, uint32_t len)
{
	const uint8_t *u, *pl;
	uint32_t ihl;
	uint16_t ulen;

	if (len < RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr) ||
	    p[12] != 0x08 || p[13] != 0x00)
		return NT_NONE;
	p += RTE_ETHER_HDR_LEN; len -= RTE_ETHER_HDR_LEN;
	ihl = (p[0] & 0x0f) * 4u;
	if ((p[0] >> 4) != 4 || ihl < sizeof(struct rte_ipv4_hdr) ||
	    p[9] != IPPROTO_UDP || len < ihl + 8)
		return NT_NONE;
	u = p + ihl;
	if ((((uint16_t)u[2] << 8) | u[3]) != NATT_PORT)
		return NT_NONE;
	ulen = ((uint16_t)u[4] << 8) | u[5];
	pl = u + 8;
	len -= ihl + 8;
	if (ulen == 9 && len >= 1 && pl[0] == 0xff)
		return NT_KEEPALIVE;
	if (len < 4)
		return NT_NONE;
	if (!pl[0] && !pl[1] && !pl[2] && !pl[3])
		return NT_IKE;
	return len >= sizeof(struct rte_esp_hdr) ? NT_ESP : NT_NONE;
}

/* RFC 4303 s3.4.3 / App. A anti-replay on an authenticated packet's 32-bit
 * sequence number: 1 = accept (and record), 0 = replay / too old.  A zero
 * window means the SA was installed with anti-replay disabled. */
int
replay_accept(struct dp_sa *ds, uint32_t lo)
{
	uint64_t t = ds->rp_top, sqn = lo;
	uint32_t w = ds->rp_w, tl = (uint32_t)t;

	if (!w)
		return 1;

	if (ds->rp_esn) {                /* RFC 4303 App. A2.2 reconstruction */
		uint64_t hi = t >> 32;
		if (tl >= w - 1) {
			if (lo < tl - w + 1) hi++;
		} else if (lo >= tl - w + 1 && hi) {
			hi--;
		}
		sqn = (hi << 32) | lo;
	}
	if (sqn == 0)
		return 0;
	if (sqn > t) {                   /* advance: clear the slots passed over */
		uint64_t d = sqn - t;
		if (d >= RP_BITS)
			memset(ds->rp_map, 0, sizeof(ds->rp_map));
		else
			for (uint64_t s = t + 1; s <= sqn; s++)
				ds->rp_map[(s % RP_BITS) / 64] &= ~(1ull << (s % 64));
		ds->rp_top = sqn;
	} else if (t - sqn >= w) {
		return 0;                    /* left of the window */
	} else if (ds->rp_map[(sqn % RP_BITS) / 64] & (1ull << (sqn % 64))) {
		return 0;                    /* seen */
	}
	ds->rp_map[(sqn % RP_BITS) / 64] |= 1ull << (sqn % 64);
	return 1;
}

/* Run n packets of ONE SA through lookaside crypto as a batch:
 * bulk op alloc -> rte_ipsec prepare -> enqueue -> dequeue (all of it) ->
 * per-op status check -> rte_ipsec process.  Every mbuf in mb[] is consumed:
 * the successfully processed ones are returned in ok[] (count returned),
 * every other one is dropped (counted, freed).  A failed op (AUTH_FAILED on
 * a forged ICV, any error) never reaches rte_ipsec_pkt_process, which does
 * not inspect op status (fail closed). */
/* Test hooks: tests/dp_path.c simulates a device that stops completing. */
#define DP_CRYPTO_SPIN_DEFAULT (1u << 24)

static inline uint16_t
crypto_deq(struct dp_wk *w, struct rte_crypto_op **ops, uint16_t n)
{
	struct dpdk_priv *d = w->d;

	if (unlikely(d->cdeq != NULL))
		return d->cdeq(d->cdev_id, w->cqp, ops, n);
	return rte_cryptodev_dequeue_burst(d->cdev_id, w->cqp, ops, n);
}

/* Reclaim ops a stuck device has since completed: their packets belong to
 * an abandoned batch (already counted as dropped), so free them.  Returns
 * the number still outstanding. */
static uint32_t
crypto_drain_stale(struct dp_wk *w)
{
	struct dpdk_priv *d = w->d;
	struct rte_crypto_op *cop[BURST_SZ];

	while (w->cq_stale) {
		uint16_t got = crypto_deq(w, cop,
		    (uint16_t)RTE_MIN(w->cq_stale, (uint32_t)BURST_SZ));
		if (!got)
			break;
		for (uint16_t i = 0; i < got; i++)
			rte_pktmbuf_free(cop[i]->sym->m_src);
		rte_mempool_put_bulk(d->cop_mp, (void **)cop, got);
		w->cq_stale -= got;
	}
	return w->cq_stale;
}

uint16_t
crypto_run(struct dp_wk *w, struct rte_ipsec_session *ss,
    struct rte_mbuf *mb[], uint16_t n, struct rte_mbuf *ok[])
{
	struct dpdk_priv *d = w->d;
	struct rte_crypto_op *cop[BURST_SZ];
	uint16_t k, enq, dq = 0, ng = 0, proc;
	unsigned spins = 0;
	int rp = !(rte_ipsec_sa_type(ss->sa) & RTE_IPSEC_SATP_DIR_MASK);  /* inbound */
	struct dp_sa *ds;

	/* A device still holding an abandoned batch gets nothing new: its next
	 * completions would be indistinguishable from this batch's. */
	if (w->cq_stale && crypto_drain_stale(w)) {
		DROP(w, DR_CRYPTO_STUCK, n);
		for (uint16_t i = 0; i < n; i++)
			rte_pktmbuf_free(mb[i]);
		return 0;
	}
	if (rte_crypto_op_bulk_alloc(d->cop_mp, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
	    cop, n) == 0) {
		for (uint16_t i = 0; i < n; i++) {
			DROP(w, DR_NOMEM, 1);
			rte_pktmbuf_free(mb[i]);
		}
		return 0;
	}
	for (uint16_t i = 0; i < n; i++)
		rte_crypto_op_attach_sym_session(cop[i], ss->crypto.ses);
	/* prepare moves the mbufs it rejected to the tail */
	k = rte_ipsec_pkt_crypto_prepare(ss, mb, cop, n);
	for (uint16_t i = k; i < n; i++) {
		DROP(w, DR_IPSEC_REJECT, 1);
		rte_pktmbuf_free(mb[i]);
	}
	enq = k ? rte_cryptodev_enqueue_burst(d->cdev_id, w->cqp, cop, k) : 0;
	for (uint16_t i = enq; i < k; i++) {
		DROP(w, DR_CRYPTO_ENQ, 1);
		rte_pktmbuf_free(mb[i]);
	}
	if (enq < n)
		rte_mempool_put_bulk(d->cop_mp, (void **)&cop[enq], n - enq);
	/* own every op before touching any mbuf again (async PMDs) */
	while (dq < enq) {
		uint16_t got = crypto_deq(w, &cop[dq], enq - dq);
		dq += got;
		if (!got && ++spins > (d->spin_max ? d->spin_max : DP_CRYPTO_SPIN_DEFAULT))
			break;
	}
	if (dq < enq) {
		/* Stuck device: the undequeued ops (and their mbufs) still belong
		 * to it.  Quarantine them -- never back to cop_mp, never touched --
		 * until crypto_drain_stale reclaims them. */
		w->cq_stale += enq - dq;
		w->n_crypto_stuck++;
		DROP(w, DR_CRYPTO_STUCK, enq - dq);
	}
	ds = rp ? sa_of_sess(d, ss) : NULL;
	for (uint16_t i = 0; i < dq; i++) {
		struct rte_mbuf *m = cop[i]->sym->m_src;
		if (cop[i]->status == RTE_CRYPTO_OP_STATUS_SUCCESS) {
			if (ds) {
				/* authenticated: now the sequence number counts */
				const struct rte_esp_hdr *eh = rte_pktmbuf_mtod_offset(
				    m, const struct rte_esp_hdr *, m->l2_len + m->l3_len);
				if (!replay_accept(ds, rte_be_to_cpu_32(eh->seq))) {
					DROP(w, DR_REPLAY, 1);
					rte_pktmbuf_free(m);
					continue;
				}
			}
			ok[ng++] = m;
		} else {
			DROP(w, DR_CRYPTO_FAIL, 1);
			rte_pktmbuf_free(m);
		}
	}
	if (dq)
		rte_mempool_put_bulk(d->cop_mp, (void **)cop, dq);
	if (!ng)
		return 0;
	/* process moves the mbufs it rejected (e.g. replay) to the tail */
	proc = rte_ipsec_pkt_process(ss, ok, ng);
	for (uint16_t i = proc; i < ng; i++) {
		DROP(w, DR_IPSEC_REJECT, 1);
		rte_pktmbuf_free(ok[i]);
	}
	return proc;
}

uint16_t
esp_inbound(struct dp_wk *w, struct rte_mbuf *bufs[], uint16_t nr,
    struct rte_mbuf *out[], uint16_t *nout)
{
	struct dpdk_priv *d = w->d;
	union rte_ipsec_sad_key kkey[BURST_SZ];
	const union rte_ipsec_sad_key *keys[BURST_SZ];
	struct rte_mbuf *pm[BURST_SZ];
	void *sas[BURST_SZ];
	uint8_t pnat[BURST_SZ];          /* arrived as ESP-in-UDP */
	uint32_t nk = 0;
	uint16_t no = 0;

	if (nr > BURST_SZ) nr = BURST_SZ;

	for (uint16_t i = 0; i < nr; i++) {
		struct rte_ether_hdr *eh =
		    rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
		struct rte_ipv4_hdr *ip;
		struct rte_esp_hdr *es;
		uint8_t ihl;
		uint16_t ipsize;
		uint16_t natlen = 0;   /* NAT-T: the 8-byte UDP header */

		/* Bounds-check against the FIRST segment (data_len), not the
		 * whole packet: a multi-segment or crafted frame must never make
		 * us read past the segment we pointer-walk. */
		if (rte_pktmbuf_data_len(bufs[i]) <
		    RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr))
			goto bad;                    /* too short for IP */
		ip = (struct rte_ipv4_hdr *)((uint8_t *)eh + RTE_ETHER_HDR_LEN);
		ihl = (ip->version_ihl & 0x0f) * 4;
		if (ihl < sizeof(struct rte_ipv4_hdr))   /* IHL < 5 */
			goto bad;
		/* NAT-T (RFC 3948): ESP directly after the UDP header on port
		 * 4500.  Strip the 8-byte UDP header before librte_ipsec, which
		 * wants bare IP+ESP; anything else UDP is not ESP. */
		natlen = 0;
		if (ip->next_proto_id == IPPROTO_UDP) {
			if (natt_class(rte_pktmbuf_mtod(bufs[i], const uint8_t *),
			    rte_pktmbuf_data_len(bufs[i])) != NT_ESP)
				goto bad;
			natlen = 8;
		}
		/* ESP header must fit within this segment after the IP header. */
		if (rte_pktmbuf_data_len(bufs[i]) <
		    RTE_ETHER_HDR_LEN + ihl + natlen + sizeof(*es))
			goto bad;
		/* IP total-length must match a sane minimum (don't trust it for
		 * crypto, but reject absurd values early). */
		ipsize = ntohs(ip->total_length);
		if (ipsize < ihl + natlen + sizeof(*es))
			goto bad;
		es = (struct rte_esp_hdr *)((uint8_t *)ip + ihl + natlen);

		/* librte_ipsec's inbound decrypt expects the bare IP+ESP packet
		 * (L2 already consumed), not the Ethernet-framed one the tap
		 * delivers.  Strip the L2 header and set l2_len=0 so the IP sits
		 * at offset 0; otherwise pofs is computed off-by-14 and the
		 * ciphertext/AAD/IV are read from the wrong bytes -> AUTH_FAILED
		 * on every real packet. */
		(void)rte_pktmbuf_adj(bufs[i], RTE_ETHER_HDR_LEN);
		ip = rte_pktmbuf_mtod(bufs[i], struct rte_ipv4_hdr *);
		if (natlen) {
			/* NAT-T: after the eth strip the frame is IP + UDP(8) +
			 * ESP.  rte_pktmbuf_adj would strip from the FRONT
			 * (the IP header), which is wrong.  Instead move the ESP payload
			 * down so it sits immediately after the IP header (bare IP + ESP
			 * for librte), then trim the now-empty UDP-header tail. */
			int payload = rte_pktmbuf_pkt_len(bufs[i]) - ihl - natlen;
			uint8_t *base = rte_pktmbuf_mtod(bufs[i], uint8_t *);
			if (payload > 0)
				memmove(base + ihl, base + ihl + natlen,
				    (size_t)payload);
			if (natlen)
				rte_pktmbuf_trim(bufs[i], natlen);
			ip = rte_pktmbuf_mtod(bufs[i], struct rte_ipv4_hdr *);
			ip->next_proto_id = IPPROTO_ESP;
			ip->total_length = rte_cpu_to_be_16((uint16_t)(ipsize - natlen));
		}
		ihl = (ip->version_ihl & 0x0f) * 4;
		es = (struct rte_esp_hdr *)((uint8_t *)ip + ihl);

		bufs[i]->l2_len = 0;
		bufs[i]->l3_len = ihl;
		/* NOTE: do NOT set RTE_MBUF_F_RX_SEC_OFFLOAD here -- that flag
		 * marks a packet already decrypted by inline hardware and is
		 * only for hardware inline offload.  On the OpenSSL CPU-crypto
		 * path (session type NONE) setting it misleads the inbound
		 * prepare about the packet's crypto state. */
		bufs[i]->packet_type = RTE_PTYPE_L3_IPV4;
		if (d->verbose) {
			fprintf(stderr,
			    "r2dp-fwd: rx pkt_len=%u data_len=%u l2_len=%u l3_len=%u "
			    "nextproto=%u dip0=%02x%02x%02x%02x\n",
			    (unsigned)rte_pktmbuf_pkt_len(bufs[i]),
			    (unsigned)rte_pktmbuf_data_len(bufs[i]),
			    (unsigned)bufs[i]->l2_len, (unsigned)bufs[i]->l3_len,
			    (unsigned)ip->next_proto_id,
			    ((uint8_t *)&ip->dst_addr)[0],
			    ((uint8_t *)&ip->dst_addr)[1],
			    ((uint8_t *)&ip->dst_addr)[2],
			    ((uint8_t *)&ip->dst_addr)[3]);
		}
		kkey[nk].v4.spi = ntohl(es->spi);
		/* SAD key is keyed on (SPI, DIP) with DIP held in raw wire-order
		 * bytes -- addr4_to_u32 (SA insert) memcpy's rsa->dst.addr[0..4]
		 * verbatim, so match that exact numeric here, NO byte-swap.
		 * rte_be_to_cpu_32() would swap it and never match an installed
		 * SA (nlook==0 on every real packet). */
		kkey[nk].v4.dip = ip->dst_addr;
		if (d->verbose) {
			fprintf(stderr,
			    "r2dp-fwd: lookup spi=%08x dip=%08x (es.spi=%08x ip.dst=%08x)\n",
			    ntohl(es->spi), rte_be_to_cpu_32(ip->dst_addr),
			    es->spi, ip->dst_addr);
		}
		keys[nk] = &kkey[nk];
		pm[nk] = bufs[i];
		pnat[nk] = natlen != 0;
		nk++;
		continue;
bad:
		/* malformed/undersized frame: drop it and move on so the rest of
		 * the burst is still processed (a `break` here would leak every
		 * remaining mbuf -- a remote pool-exhaustion DoS). */
		DROP(w, DR_MALFORMED, 1);
		rte_pktmbuf_free(bufs[i]);
	}
	if (nk == 0) {
		if (nout) *nout = 0;
		return 0;
	}

	uint32_t nlook = rte_ipsec_sad_lookup(d->sad, keys, sas, nk);

	if (d->verbose) {
		fprintf(stderr, "r2dp-fwd: esp_inbound nk=%u nlook=%u\n",
		    (unsigned)nk, (unsigned)nlook);
	}

	if (nlook == 0) {
		/* no SA matched -- drop the whole burst */
		DROP(w, DR_NO_SA_IN, nk);
		for (uint32_t i = 0; i < nk; i++)
			rte_pktmbuf_free(pm[i]);
		if (nout) *nout = 0;
		return nk;
	}

	/* The framing must match the SA (RFC 3948 s3.1): plain ESP for a
	 * NAT-T SA, or ESP-in-UDP for a plain one, is dropped before crypto. */
	for (uint32_t i = 0; i < nk; i++) {
		const struct dp_sa *ds;
		if (!sas[i])
			continue;
		ds = sa_of_sess(d, sas[i]);
		if (ds && (ds->natt == R2DP_NATT_ESPINUDP) != pnat[i]) {
			DROP(w, DR_ENCAP, 1);
			rte_pktmbuf_free(pm[i]);
			pm[i] = NULL;
			sas[i] = NULL;
		} else if (ds && ds->owner != w->id) {
			/* another worker owns this SA's replay window */
			DROP(w, DR_STEER, 1);
			rte_pktmbuf_free(pm[i]);
			pm[i] = NULL;
			sas[i] = NULL;
		}
	}

	/* Batch per run of packets on the same SA: one bulk op alloc, prepare,
	 * enqueue and dequeue per run instead of per packet. */
	for (uint32_t i = 0; i < nk; ) {
		struct rte_ipsec_session *ss = sas[i];
		struct rte_mbuf *ok[BURST_SZ];
		uint32_t j = i + 1;
		uint16_t ng;

		if (ss == NULL) {
			if (pm[i]) {               /* no SA: drop */
				DROP(w, DR_NO_SA_IN, 1);
				rte_pktmbuf_free(pm[i]);
			}
			i++;
			continue;
		}
		while (j < nk && sas[j] == ss)
			j++;
		ng = crypto_run(w, ss, &pm[i], (uint16_t)(j - i), ok);
		for (uint16_t k = 0; k < ng; k++) {
			/* D8: RFC 4301 s5.2 IN selector check + trim to inner IP */
			if (out && no < BURST_SZ && in_inner_ok(d, ss, ok[k])) {
				sa_bytes_add(d, ss, rte_pktmbuf_pkt_len(ok[k]));
				out[no++] = ok[k];
			} else {
				if (d->verbose)
					fprintf(stderr, "r2dp-fwd: inner SEL reject\n");
				DROP(w, DR_INNER_SEL, 1);
				rte_pktmbuf_free(ok[k]);
			}
		}
		i = j;
	}
	(void)nlook;
	if (nout) *nout = no;
	return nk;
}

/* Validate + trim a decrypted inner packet and apply inbound_policy_ok. */
int
in_inner_ok(struct dpdk_priv *d, struct rte_ipsec_session *ss,
    struct rte_mbuf *mb)
{
	struct rte_ipv4_hdr *ip;
	struct dp_sa *ds = sa_of_sess(d, ss);
	uint8_t ihl;
	uint16_t iplen, cur;

	if (ds == NULL || rte_pktmbuf_pkt_len(mb) < sizeof(struct rte_ipv4_hdr))
		return 0;
	ip = rte_pktmbuf_mtod(mb, struct rte_ipv4_hdr *);
	if ((ip->version_ihl >> 4) != 4)
		return 0;
	ihl = (ip->version_ihl & 0x0f) * 4;
	if (ihl < (uint8_t)sizeof(struct rte_ipv4_hdr) ||
	    ihl > rte_pktmbuf_data_len(mb))
		return 0;
	/* trim any trailing bytes beyond the inner IP length (padding/NAT-T) */
	iplen = rte_be_to_cpu_16(ip->total_length);
	cur = rte_pktmbuf_pkt_len(mb);
	if (iplen < cur)
		rte_pktmbuf_trim(mb, cur - iplen);
	return inbound_policy_ok(d, ds, (const uint8_t *)ip,
	    rte_pktmbuf_data_len(mb));
}

/* Outbound ESP: take inner IPv4 plaintext (L2 already stripped, l2_len=0),
 * look up the OUT policy + EGRESS SA, run rte_ipsec EGRESS encrypt, and write
 * the resulting ESP datagram (outer IP + ESP, L2 NOT yet re-added) into `out`.
 * Non-protected packets are left alone (returned as unchanged bypass). */
void
esp_outbound(struct dp_wk *w, struct rte_mbuf *bufs[], uint16_t nr,
    struct rte_mbuf *out[], uint16_t *nout, uint16_t *nbypass)
{
	struct dpdk_priv *d = w->d;
	uint16_t no = 0, nb = 0, nm = 0;
	struct rte_mbuf *pm[BURST_SZ];
	struct dp_sa *pds[BURST_SZ];
	enum dp_drop why = DR_MALFORMED;

	const struct rte_ipv4_hdr *cip[BURST_SZ] = { NULL };
	const struct r2dp_sp *csp[BURST_SZ];
	struct dp_sa *cds[BURST_SZ];
	size_t cav[BURST_SZ] = { 0 };

	if (nr > BURST_SZ) nr = BURST_SZ;
	/* inner tap delivers Ethernet: parse the inner IP at the L2 offset for
	 * policy matching (one ACL classify for the whole burst); only STRIP
	 * L2 below for a matched packet so the unconsumed (bypass) mbufs keep
	 * their frame for forwarding. */
	for (uint16_t i = 0; i < nr; i++) {
		const struct rte_ipv4_hdr *ip;

		cip[i] = NULL;
		cav[i] = 0;
		if (rte_pktmbuf_data_len(bufs[i]) <
		    RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr))
			continue;
		ip = (const struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(bufs[i],
		    const uint8_t *) + RTE_ETHER_HDR_LEN);
		if ((ip->version_ihl >> 4) != 4)
			continue;
		cip[i] = ip;
		cav[i] = rte_pktmbuf_data_len(bufs[i]) - RTE_ETHER_HDR_LEN;
	}
	sp_match_out_burst(d, cip, cav, nr, csp, cds);
	for (uint16_t i = 0; i < nr; i++) {
		struct dp_sa *ds = cds[i];
		const struct r2dp_sp *sp = csp[i];
		uint8_t ihl;
		struct rte_ipv4_hdr *lip;

		if (!sp) { nb++; continue; }   /* no matching OUT policy: bypass */

		/* A matched policy decides the disposition (H2, RFC 4301 5.1):
		 * DISCARD always drops; PROTECT with no SA drops (fail-closed, the
		 * SA must exist before we protect); only BYPASS forwards clear. */
		why = DR_POLICY_DISCARD;
		if (sp->action == R2DP_ACT_DISCARD)
			goto drop;
		why = DR_NO_SA_OUT;
		if (sp->action == R2DP_ACT_PROTECT && !ds)
			goto drop;
		if (sp->action != R2DP_ACT_PROTECT) { nb++; continue; } /* BYPASS */
		why = DR_STEER;          /* SA (and its sequence) owned elsewhere */
		if (ds->owner != w->id)
			goto drop;

		/* Once the packet matched a policy, failure below must DROP it, never
		 * leak it back as cleartext: the L2 header is about to be stripped,
		 * so the mbuf is no longer a forwardable frame (H4/H2). */
		(void)rte_pktmbuf_adj(bufs[i], RTE_ETHER_HDR_LEN);
		bufs[i]->l2_len = 0;
		lip = rte_pktmbuf_mtod(bufs[i], struct rte_ipv4_hdr *);
		ihl = (lip->version_ihl & 0x0f) * 4;
		why = DR_MALFORMED;
		if (ihl < 20 || ihl > rte_pktmbuf_data_len(bufs[i]))
			goto drop;   /* M5c: reject malformed/oversized IHL */
		bufs[i]->l3_len = ihl;
		bufs[i]->packet_type = RTE_PTYPE_L3_IPV4;
		/* M5a: drop Ethernet padding.  A short inner IP (< 60B with the tap's
		 * eth frame) carries trailing pad after ip->total_length; that pad
		 * would be encrypted into the ESP payload and break the inner ICV at
		 * a real peer that authenticated only the padded length.  Trim to
		 * the IP length so the ESP payload carries exactly the inner packet. */
		{
			uint16_t iplen = rte_be_to_cpu_16(lip->total_length);
			uint16_t cur = rte_pktmbuf_pkt_len(bufs[i]);
			if (iplen < cur)
				rte_pktmbuf_trim(bufs[i], cur - iplen);
		}

		/* matched + PROTECT + SA: queue for the batched crypto pass */
		pm[nm] = bufs[i];
		pds[nm++] = ds;
		bufs[i] = NULL;
		continue;
drop:
		/* Single drop path: never forward cleartext after a policy matched,
		 * and never leak the mbuf (H4).  Count and mark the slot NULL so
		 * worker_inner does not forward or free it again. */
		DROP(w, why, 1);
		rte_pktmbuf_free(bufs[i]);
		bufs[i] = NULL;
	}

	/* batched crypto, one run per SA (bursts are usually one flow) */
	for (uint16_t i = 0; i < nm; ) {
		struct dp_sa *ds = pds[i];
		struct rte_mbuf *ok[BURST_SZ];
		uint16_t j = i + 1, ng;

		while (j < nm && pds[j] == ds)
			j++;
		ng = crypto_run(w, &ds->sess, &pm[i], j - i, ok);
		for (uint16_t k = 0; k < ng; k++) {
			struct rte_mbuf *m = ok[k];
			uint16_t proc = 1;

			if (!out || no >= BURST_SZ) {
				DROP(w, DR_NOMEM, 1);
				rte_pktmbuf_free(m);
				continue;
			}
			/* byte-lifetime: count the crypted bytes on this egress SA */
			__atomic_fetch_add(&ds->bytes, rte_pktmbuf_pkt_len(m),
			    __ATOMIC_RELAXED);
			{
				struct rte_ipv4_hdr *oip =
				    rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
				/* NAT-T egress (RFC 3948 s2.1): insert an 8-byte UDP header
				 * after the outer IP, ESP right behind it (no marker: that
				 * is IKE's), ports as iked negotiated, checksum 0. */
				if (ds->natt == R2DP_NATT_ESPINUDP && oip &&
				    (oip->version_ihl >> 4) == 4) {
					uint8_t ihl = (oip->version_ihl & 0x0f) * 4;
					uint32_t len = rte_pktmbuf_pkt_len(m);
					uint8_t *base = rte_pktmbuf_mtod(m, uint8_t*);
					uint16_t plen;
					if (rte_pktmbuf_append(m, 8)) {
						struct rte_udp_hdr *uh;
						memmove(base + ihl + 8, base + ihl,
						    len - ihl);
						uh = (struct rte_udp_hdr *)(base + ihl);
						uh->src_port = ds->natt_sport;
						uh->dst_port = ds->natt_dport;
						plen = (uint16_t)(len - ihl + 8);
						uh->dgram_len = rte_cpu_to_be_16(plen);
						uh->dgram_cksum = 0;
						oip->next_proto_id = IPPROTO_UDP;
						oip->total_length = rte_cpu_to_be_16(
						    (uint16_t)(len + 8));
						oip->hdr_checksum = 0;
					} else {
						/* no tailroom: never send it as bare ESP */
						DROP(w, DR_NOMEM, 1);
						rte_pktmbuf_free(m);
						continue;
					}
				}
				/* librte's outbound tunnel prepare only patches
				 * total_length/packet_id; it leaves hdr_checksum=0, which
				 * every real peer drops (ip_rcv -> InHdrErrors).  Compute
				 * it here (H1). */
				if ((oip->version_ihl >> 4) == 4) {
					oip->hdr_checksum = 0;
					oip->hdr_checksum = rte_ipv4_cksum(oip);
				}
				if (d->verbose) {
					uint8_t *b = rte_pktmbuf_mtod(m, uint8_t *);
					fprintf(stderr,
					    "r2dp-fwd: egress-proc proc=%u pkt=%u b0=%02x%02x%02x%02x%02x%02x%02x%02x\n",
					    proc, (unsigned)rte_pktmbuf_pkt_len(m),
					    b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]);
				}
			}
			(void)proc;
			w->n_esp++;
			out[no++] = m;
		}
		i = j;
	}
	if (nout) *nout = no;
	if (nbypass) *nbypass = nb;
}


#endif /* R2DP_HAVE_DPDK */

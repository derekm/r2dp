/*
 * dp_path: end-to-end data-path test through the production fwd/dp_dpdk.c
 * (included directly) on the crypto_openssl vdev under ASan/UBSan:
 *
 *   inner frame -> esp_outbound (forwarder A: OUT policy + EGRESS SA)
 *               -> ESP datagram -> esp_inbound (forwarder B: INGRESS SA +
 *                  IN policy) -> inner packet, byte-identical.
 *
 * Also checks the policy dispositions on the real path: an inner packet
 * outside B's IN selectors is dropped after decrypt (M5), a port-specific
 * DISCARD overrides a covering PROTECT (M5), PROTECT without an SA drops.
 * Runs in CI's DPDK lanes (R2DP_REQUIRE_DPDK=1 turns SKIP into failure).
 */
#include "../fwd/dp_dpdk.c"

static int fails;
#define CHECK(c, m) do { if (c) printf("ok   %s\n", m); \
	else { printf("FAIL %s\n", m); fails++; } } while (0)

static uint8_t key[20] = { 9,8,7,6,5,4,3,2,1,0,1,2,3,4,5,6, 0xde,0xad,0xbe,0xef };
static struct rte_mempool *mp;
static int cdev = -1;

static struct dpdk_priv *
mk_priv(const char *tag)
{
	struct dpdk_priv *d = aligned_alloc(RTE_CACHE_LINE_SIZE, sizeof(*d));
	struct rte_ipsec_sad_conf sc;
	char n[32];

	if (!d)
		return NULL;
	memset(d, 0, sizeof(*d));
	d->cdev_id = (uint8_t)cdev;
	d->have_cdev = 1;
	snprintf(n, sizeof(n), "%s_sess", tag);
	d->sess_mp = rte_cryptodev_sym_session_pool_create(n, 64,
	    rte_cryptodev_sym_get_private_session_size(d->cdev_id), 0, 0,
	    SOCKET_ID_ANY);
	snprintf(n, sizeof(n), "%s_cop", tag);
	d->cop_mp = rte_crypto_op_pool_create(n, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
	    64, 0, sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op) +
	    R2DP_GCM_IV_LEN, SOCKET_ID_ANY);
	memset(&sc, 0, sizeof(sc));
	sc.socket_id = SOCKET_ID_ANY;
	sc.max_sa[RTE_IPSEC_SAD_SPI_DIP] = 64;
	sc.flags = RTE_IPSEC_SAD_FLAG_RW_CONCURRENCY;
	snprintf(n, sizeof(n), "%s_sad", tag);
	d->sad = rte_ipsec_sad_create(n, &sc);
	if (!d->sess_mp || !d->cop_mp || !d->sad)
		return NULL;
	rte_spinlock_init(&d->lock);
	return d;
}

static void
free_priv(struct dpdk_priv *d)
{
	for (int i = 0; i < MAX_SA; i++) {
		if (d->sa_tab[i].used)
			sa_slot_free(d, &d->sa_tab[i]);
	}
	spd_teardown(d);
	rte_ipsec_sad_destroy(d->sad);
	rte_mempool_free(d->sess_mp);
	rte_mempool_free(d->cop_mp);
	free(d);
}

static void
mk_sa(struct r2dp_sa *r, uint32_t spi)
{
	memset(r, 0, sizeof(*r));
	r->proto = R2DP_PROTO_ESP; r->mode = R2DP_MODE_TUNNEL;
	r->enc = R2DP_ENCR_AES_GCM_16; r->spi = htonl(spi); r->enckeylen = 20;
	r->src.family = r->dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "192.0.2.1", r->src.addr);
	inet_pton(AF_INET, "192.0.2.2", r->dst.addr);
}

static void
add_sp(struct dpdk_priv *d, uint32_t slid, uint8_t dir, uint8_t act,
    const char *s, uint8_t ps, const char *t, uint8_t pt,
    uint8_t ulp, uint16_t dport)
{
	struct fwd_dp dp = { .priv = d };
	struct r2dp_sp sp;

	memset(&sp, 0, sizeof(sp));
	sp.slid = slid; sp.dir = dir; sp.action = act; sp.ul_proto = ulp;
	sp.sel_src.family = sp.sel_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, s, sp.sel_src.addr); sp.pref_src = ps;
	inet_pton(AF_INET, t, sp.sel_dst.addr); sp.pref_dst = pt;
	sp.sel_dst.port = htons(dport);
	sp.tun_src.family = sp.tun_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "192.0.2.1", sp.tun_src.addr);
	inet_pton(AF_INET, "192.0.2.2", sp.tun_dst.addr);
	dpd_sp_add(&dp, &sp);
}

/* Ethernet + IPv4 inner frame (64-byte IP packet). */
static struct rte_mbuf *
inner_frame_len(const char *src, const char *dst, uint8_t proto, uint16_t dport,
    uint8_t *ipcopy, uint16_t len)
{
	struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
	uint8_t *f;

	if (!m)
		return NULL;
	f = (uint8_t *)rte_pktmbuf_append(m, 14 + len);
	if (!f) { rte_pktmbuf_free(m); return NULL; }
	memset(f, 0, 14 + len);
	f[12] = 0x08;
	f[14] = 0x45; f[16] = (uint8_t)(len >> 8); f[17] = (uint8_t)len;
	f[22] = 64; f[23] = proto;
	inet_pton(AF_INET, src, f + 14 + 12);
	inet_pton(AF_INET, dst, f + 14 + 16);
	f[14 + 20 + 2] = (uint8_t)(dport >> 8); f[14 + 20 + 3] = (uint8_t)dport;
	for (int i = 28; i < len; i++) f[14 + i] = (uint8_t)i;
	((struct rte_ipv4_hdr *)(f + 14))->hdr_checksum =
	    rte_ipv4_cksum((struct rte_ipv4_hdr *)(f + 14));
	if (ipcopy)
		memcpy(ipcopy, f + 14, len);
	return m;
}

static struct rte_mbuf *
inner_frame(const char *src, const char *dst, uint8_t proto, uint16_t dport,
    uint8_t *ipcopy)
{
	return inner_frame_len(src, dst, proto, dport, ipcopy, 64);
}

/* A -> encrypt -> B -> decrypt.  Returns 1 if an inner packet came out of
 * B (copied to `got`), 0 if dropped; *encrypted says whether A emitted ESP. */
static int tamper_at = -1;   /* >= 0: flip this byte of the ESP datagram */

static struct dp_worker wa, wb;   /* per-side data-path worker (queue/qp 0) */

static int
run_len(struct dp_worker *wa_, struct dp_worker *wb_, struct rte_mbuf *m,
    int *encrypted, uint8_t *got, uint16_t len)
{
	struct rte_mbuf *in[1] = { m }, *esp[1] = { NULL }, *dec[BURST_SZ];
	uint16_t nout = 0, nb = 0, ndec = 0;

	esp_outbound(wa_, in, 1, esp, &nout, &nb);
	*encrypted = nout == 1;
	if (nb && in[0])
		rte_pktmbuf_free(in[0]);          /* bypass: caller would forward */
	if (nout != 1)
		return 0;
	if (!rte_pktmbuf_prepend(esp[0], 14)) { rte_pktmbuf_free(esp[0]); return 0; }
	{
		uint8_t *f = rte_pktmbuf_mtod(esp[0], uint8_t *);
		memset(f, 0, 14); f[12] = 0x08;
		if (tamper_at >= 0 && (uint32_t)tamper_at + 14 < rte_pktmbuf_data_len(esp[0]))
			f[14 + tamper_at] ^= 0x01;
	}
	esp_inbound(wb_, esp, 1, dec, &ndec);
	if (ndec != 1)
		return 0;
	memcpy(got, rte_pktmbuf_mtod(dec[0], uint8_t *),
	    RTE_MIN((uint32_t)len, rte_pktmbuf_pkt_len(dec[0])));
	ndec = (uint16_t)rte_pktmbuf_pkt_len(dec[0]);
	rte_pktmbuf_free(dec[0]);
	return ndec == len;
}

static int
run(struct dp_worker *wa_, struct dp_worker *wb_, struct rte_mbuf *m,
    int *encrypted, uint8_t *got)
{
	return run_len(wa_, wb_, m, encrypted, got, 64);
}

int
main(void)
{
	char *ea[] = { "dp_path", "--no-huge", "--no-pci", "-m", "256",
	    "--vdev=crypto_openssl0", "--log-level=1", NULL };
	struct rte_cryptodev_config cc;
	struct rte_cryptodev_qp_conf qc;
	struct dpdk_priv *a, *b;
	struct r2dp_sa r;
	uint8_t want[64], got[64];
	int enc;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (rte_eal_init(7, ea) < 0 ||
	    (cdev = rte_cryptodev_get_dev_id("crypto_openssl0")) < 0) {
		if (getenv("R2DP_REQUIRE_DPDK")) { puts("DPDK setup FAILED"); return 1; }
		puts("SKIP: EAL/crypto_openssl"); return 77;
	}
	memset(&cc, 0, sizeof(cc)); cc.socket_id = SOCKET_ID_ANY; cc.nb_queue_pairs = 1;
	memset(&qc, 0, sizeof(qc)); qc.nb_descriptors = 256;
	if (rte_cryptodev_configure(cdev, &cc) < 0 ||
	    rte_cryptodev_queue_pair_setup(cdev, 0, &qc, SOCKET_ID_ANY) < 0 ||
	    rte_cryptodev_start(cdev) < 0) { puts("cryptodev FAILED"); return 1; }
	mp = rte_pktmbuf_pool_create("dp_path_mb", 256, 0, 0,
	    RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	a = mk_priv("A"); b = mk_priv("B");
	memset(&wa, 0, sizeof(wa)); memset(&wb, 0, sizeof(wb));
	wa.d = a; wb.d = b; wa.qid = 0; wb.qid = 0; wa.cqp = 0; wb.cqp = 0;
	if (!mp || !a || !b) { puts("setup FAILED"); return 1; }

	/* A: wide OUT PROTECT 10.0.0.0/16 -> 10.0.0.0/16 + EGRESS SA */
	add_sp(a, 1, R2DP_DIR_OUT, R2DP_ACT_PROTECT, "10.0.0.0", 16, "10.0.0.0", 16,
	    R2DP_PROTO_ANY, 0);
	/* B: IN PROTECT only for 10.0.1.0/24 -> 10.0.2.0/24 */
	add_sp(b, 1, R2DP_DIR_IN, R2DP_ACT_PROTECT, "10.0.1.0", 24, "10.0.2.0", 24,
	    R2DP_PROTO_ANY, 0);

	/* PROTECT with no SA yet: dropped, never sent in clear */
	{
		struct rte_mbuf *m = inner_frame("10.0.1.5", "10.0.2.5", 1, 0, want);
		CHECK(!run(&wa, &wb, m, &enc, got) && !enc, "PROTECT without SA -> drop");
	}

	mk_sa(&r, 0x5001); r.dir = R2DP_DIR_OUT;
	CHECK(sa_install(a, &r, key, 20, 0, 0) == 0, "A: egress SA installed");
	mk_sa(&r, 0x5001); r.dir = R2DP_DIR_IN;
	CHECK(sa_install(b, &r, key, 20, 0, 1) == 0, "B: ingress SA installed");

	{
		struct rte_mbuf *m = inner_frame("10.0.1.5", "10.0.2.5", 1, 0, want);
		int ok = run(&wa, &wb, m, &enc, got);
		CHECK(enc, "A encrypts the matching flow");
		CHECK(ok && memcmp(got, want, 64) == 0,
		    "B decrypts it byte-identical (outbound -> inbound round trip)");
	}
	{
		/* matches A's wide OUT policy, but not B's IN selectors */
		struct rte_mbuf *m = inner_frame("10.0.9.5", "10.0.2.5", 1, 0, want);
		int ok = run(&wa, &wb, m, &enc, got);
		CHECK(enc && !ok, "inner packet outside B's IN selector dropped after decrypt");
	}

	/* A forged datagram must never decrypt to cleartext: flip a ciphertext
	 * byte (after outer IP 20 + ESP hdr 8 + IV 8) and the ICV's last byte. */
	{
		static uint8_t w[64], g[64];
		struct rte_mbuf *m;
		tamper_at = 20 + 8 + 8 + 4;
		m = inner_frame("10.0.1.5", "10.0.2.5", 1, 0, w);
		CHECK(!run(&wa, &wb, m, &enc, g) && enc, "tampered ciphertext -> dropped (auth failure honoured)");
		tamper_at = 20 + 8 + 8 + 64 + 2 + 2 + 15;   /* inside the 16-B ICV */
		m = inner_frame("10.0.1.5", "10.0.2.5", 1, 0, w);
		CHECK(!run(&wa, &wb, m, &enc, g) && enc, "tampered ICV -> dropped");
		tamper_at = -1;
	}

	/* Inner lengths whose low byte is < 20 (256, 512, 513, 270...) were
	 * dropped by an 8-bit truncation of the mbuf length in the IHL check. */
	{
		static const uint16_t lens[] = { 255, 256, 257, 269, 270, 276, 512, 513, 1024, 1400 };
		static uint8_t w[1500], g[1500];
		int allok = 1;
		for (unsigned k = 0; k < RTE_DIM(lens); k++) {
			struct rte_mbuf *m = inner_frame_len("10.0.1.5", "10.0.2.5", 1, 0, w, lens[k]);
			int ok = m && run_len(&wa, &wb, m, &enc, g, lens[k]) && memcmp(g, w, lens[k]) == 0;
			if (!ok) { printf("     len %u failed\n", lens[k]); allok = 0; }
		}
		CHECK(allok, "inner lengths 255..1400 incl. 256/512/513 round-trip");
	}

	/* Batched crypto: a 32-packet burst (every 8th outside A's policy ->
	 * bypass) is encrypted in one run; packet 5 is then forged.  Exactly the
	 * other protected packets decrypt, in order, byte-identical. */
	{
		enum { N = 32 };
		static uint8_t w[N][64];
		struct rte_mbuf *in[N], *esp[N], *dec[BURST_SZ];
		uint16_t nout = 0, nb = 0, ndec = 0, nprot = 0, good = 1;

		for (int k = 0; k < N; k++) {
			char src[32];
			snprintf(src, sizeof(src), k % 8 == 7 ? "10.1.0.%d" : "10.0.1.%d", k + 1);
			in[k] = inner_frame(src, "10.0.2.5", 17, 1000 + k, w[k]);
			nprot += k % 8 != 7;
		}
		esp_outbound(&wa, in, N, esp, &nout, &nb);
		CHECK(nout == nprot && nb == N - nprot, "burst: one batched encrypt, bypass left alone");
		for (int k = 0; k < N; k++)
			if (in[k]) rte_pktmbuf_free(in[k]);
		for (uint16_t k = 0; k < nout; k++) {
			uint8_t *f = (uint8_t *)rte_pktmbuf_prepend(esp[k], 14);
			memset(f, 0, 14); f[12] = 0x08;
			if (k == 5) f[14 + 40] ^= 1;
		}
		esp_inbound(&wb, esp, nout, dec, &ndec);
		CHECK(ndec == nout - 1, "burst: forged packet dropped, the rest decrypt");
		for (uint16_t k = 0, src = 0; k < ndec; k++, src++) {
			while (src % 8 == 7 || src == 5) src++;   /* skip bypass + forged */
			if (memcmp(rte_pktmbuf_mtod(dec[k], uint8_t *), w[src], 64)) good = 0;
			rte_pktmbuf_free(dec[k]);
		}
		CHECK(good, "burst: decrypted in order, byte-identical");
	}

	/* port-specific DISCARD (TCP/23) overrides the covering PROTECT */
	add_sp(a, 2, R2DP_DIR_OUT, R2DP_ACT_DISCARD, "10.0.0.0", 16, "10.0.0.0", 16,
	    6, 23);
	{
		struct rte_mbuf *m = inner_frame("10.0.1.5", "10.0.2.5", 6, 23, want);
		CHECK(!run(&wa, &wb, m, &enc, got) && !enc, "TCP/23 DISCARD honoured (port selector)");
		m = inner_frame("10.0.1.5", "10.0.2.5", 6, 22, want);
		CHECK(run(&wa, &wb, m, &enc, got) && enc, "TCP/22 still protected end to end");
	}

	/* anti-replay: the same ESP datagram delivered twice is accepted once;
	 * an out-of-order older one inside the window is accepted once too */
	{
		static uint8_t w[64];
		struct rte_mbuf *in[2], *esp[2], *dup[2], *dec[BURST_SZ];
		uint16_t nout = 0, nb = 0, n1 = 0, n2 = 0, n3 = 0, n4 = 0;
		uint64_t rej = b->n_dropr[DR_REPLAY];
		in[0] = inner_frame("10.0.1.5", "10.0.2.5", 1, 0, w);
		in[1] = inner_frame("10.0.1.6", "10.0.2.5", 1, 0, w);
		esp_outbound(&wa, in, 2, esp, &nout, &nb);
		for (int k = 0; k < 2; k++) {
			uint8_t *f = (uint8_t *)rte_pktmbuf_prepend(esp[k], 14);
			memset(f, 0, 14); f[12] = 0x08;
			dup[k] = rte_pktmbuf_copy(esp[k], mp, 0, UINT32_MAX);
		}
		esp_inbound(&wb, &esp[1], 1, dec, &n1);           /* seq N+1 */
		for (uint16_t k = 0; k < n1; k++) rte_pktmbuf_free(dec[k]);
		esp_inbound(&wb, &esp[0], 1, dec, &n2);           /* seq N, older */
		for (uint16_t k = 0; k < n2; k++) rte_pktmbuf_free(dec[k]);
		esp_inbound(&wb, &dup[0], 1, dec, &n3);           /* replay N */
		for (uint16_t k = 0; k < n3; k++) rte_pktmbuf_free(dec[k]);
		esp_inbound(&wb, &dup[1], 1, dec, &n4);           /* replay N+1 */
		for (uint16_t k = 0; k < n4; k++) rte_pktmbuf_free(dec[k]);
		printf("     replay: n1=%u n2=%u n3=%u n4=%u\n", n1, n2, n3, n4);
		CHECK(nout == 2 && n1 == 1 && n2 == 1, "replay: in-window reordering accepted");
		CHECK(n3 == 0 && n4 == 0 && b->n_dropr[DR_REPLAY] == rej + 2,
		    "replay: duplicates dropped (replay)");
	}

	/* per-reason drop counters account for every drop above */
	{
		uint64_t sa = 0, sb = 0;
		char buf[1024] = "";
		FILE *f = tmpfile();
		for (int r = 0; r < DR_NUM; r++) { sa += wa.n_dropr[r]; sb += wb.n_dropr[r]; }
		CHECK(sa == wa.n_drop && sb == wb.n_drop, "drops: reasons sum to n_drop");
		CHECK(wa.n_dropr[DR_NO_SA_OUT] == 1, "drops: PROTECT without SA -> no_sa_out");
		CHECK(wa.n_dropr[DR_POLICY_DISCARD] == 1, "drops: TCP/23 -> policy_discard");
		CHECK(wb.n_dropr[DR_CRYPTO_FAIL] == 3, "drops: 3 forged datagrams -> crypto_fail");
		CHECK(wb.n_dropr[DR_INNER_SEL] == 1, "drops: off-selector inner -> inner_sel");
		if (f) {
			size_t n;
			dpd_stats_dump(b, f);
			rewind(f);
			n = fread(buf, 1, sizeof(buf) - 1, f);
			buf[n] = 0;
			fclose(f);
		}
		CHECK(strstr(buf, " crypto_fail=3 ") && strstr(buf, " inner_sel=1 "),
		    "drops: stats dump names each reason");
	}

	free_priv(a); free_priv(b);
	rte_mempool_free(mp);
	rte_cryptodev_stop(cdev);
	rte_cryptodev_close(cdev);
	rte_eal_cleanup();
	if (fails) { printf("dp_path: %d failures\n", fails); return 1; }
	puts("dp_path: OK");
	return 0;
}

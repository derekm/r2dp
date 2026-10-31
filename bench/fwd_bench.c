/*
 * fwd_bench: data-path cost of the production fwd/dp_dpdk.c (included
 * directly) on the crypto_openssl vdev, in TSC cycles per packet:
 *
 *   inner frame -> esp_outbound (A: OUT policy + EGRESS SA)  "enc"
 *   ESP frame   -> esp_inbound  (B: INGRESS SA + IN policy)  "dec"
 *
 * measured with 1, 65 and 201 configured tunnels (one carries the traffic,
 * the others are unrelated SAs + policies on both sides), 32-packet bursts.
 *
 *   fwd_bench [--check] [SIZE]
 *
 * --check makes it a regression test (meson `benchmark`, CI):
 *   - scaling: cycles at 201 tunnels <= R2DP_BENCH_MAX_SCALE (default 1.5)
 *     x cycles at 1 tunnel, for enc and dec -- machine independent, and
 *     exactly what a per-packet table scan breaks;
 *   - absolute: enc and dec at 1 tunnel <= R2DP_BENCH_MAX_CYC (default
 *     8000) cycles/pkt -- generous, catches order-of-magnitude losses;
 *     R2DP_BENCH_MAX_CYC=0 disables it (sanitizer builds).
 * Exit 77 (skip) without EAL/crypto_openssl unless R2DP_REQUIRE_DPDK=1.
 */
#include "dpdk_int.h"

#define NPKT 16384
#define BURST 32

static uint8_t key[20] = { 9,8,7,6,5,4,3,2,1,0,1,2,3,4,5,6, 0xde,0xad,0xbe,0xef };
static struct rte_mempool *mp;
static int cdev = -1;
static struct rte_mbuf *espq[NPKT];

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
	d->sess_mp = rte_cryptodev_sym_session_pool_create(n, 2 * MAX_SA,
	    rte_cryptodev_sym_get_private_session_size(d->cdev_id), 0, 0,
	    SOCKET_ID_ANY);
	snprintf(n, sizeof(n), "%s_cop", tag);
	d->cop_mp = rte_crypto_op_pool_create(n, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
	    4096, 128, sizeof(struct rte_crypto_op) +
	    sizeof(struct rte_crypto_sym_op) + R2DP_GCM_IV_LEN, SOCKET_ID_ANY);
	memset(&sc, 0, sizeof(sc));
	sc.socket_id = SOCKET_ID_ANY;
	sc.max_sa[RTE_IPSEC_SAD_SPI_DIP] = 2 * MAX_SA;
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
	for (int i = 0; i < MAX_SA; i++)
		if (d->sa_tab[i].used)
			sa_slot_free(d, &d->sa_tab[i]);
	spd_teardown(d);
	rte_ipsec_sad_destroy(d->sad);
	rte_mempool_free(d->sess_mp);
	rte_mempool_free(d->cop_mp);
	free(d);
}

static void
mk_sa(struct r2dp_sa *r, uint32_t spi, const char *src, const char *dst)
{
	memset(r, 0, sizeof(*r));
	r->proto = R2DP_PROTO_ESP; r->mode = R2DP_MODE_TUNNEL;
	r->enc = R2DP_ENCR_AES_GCM_16; r->spi = htonl(spi); r->enckeylen = 20;
	r->wsize = 64;
	r->src.family = r->dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, src, r->src.addr);
	inet_pton(AF_INET, dst, r->dst.addr);
}

static int
add_sp(struct dpdk_priv *d, uint32_t slid, uint8_t dir, const char *s,
    const char *t, const char *ts, const char *td)
{
	struct fwd_dp dp = { .priv = d };
	struct r2dp_sp sp;

	memset(&sp, 0, sizeof(sp));
	sp.slid = slid; sp.dir = dir; sp.action = R2DP_ACT_PROTECT;
	sp.ul_proto = R2DP_PROTO_ANY; sp.mode = R2DP_MODE_TUNNEL;
	sp.protos = R2DP_SPP_ESP;
	sp.sel_src.family = sp.sel_dst.family = R2DP_AF_INET4;
	sp.tun_src.family = sp.tun_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, s, sp.sel_src.addr); sp.pref_src = 24;
	inet_pton(AF_INET, t, sp.sel_dst.addr); sp.pref_dst = 24;
	inet_pton(AF_INET, ts, sp.tun_src.addr);
	inet_pton(AF_INET, td, sp.tun_dst.addr);
	return dpd_sp_add(&dp, &sp);
}

/* unrelated tunnel #i on both sides */
static int
add_tunnel(struct dpdk_priv *a, struct dpdk_priv *b, int i)
{
	char s[32], t[32], peer[32];
	struct r2dp_sa r;

	snprintf(s, sizeof(s), "172.16.%d.0", i);
	snprintf(t, sizeof(t), "172.17.%d.0", i);
	snprintf(peer, sizeof(peer), "198.51.%d.%d", 100 + i / 250, i % 250 + 1);
	mk_sa(&r, 0x9000 + i, "192.0.2.1", peer); r.dir = R2DP_DIR_OUT;
	if (sa_install(a, &r, key, 20, 0, 0)) return -1;
	mk_sa(&r, 0x9000 + i, peer, "192.0.2.2"); r.dir = R2DP_DIR_IN;
	if (sa_install(b, &r, key, 20, 0, 1)) return -1;
	if (add_sp(a, 1000 + i, R2DP_DIR_OUT, s, t, "192.0.2.1", peer)) return -1;
	return add_sp(b, 1000 + i, R2DP_DIR_IN, t, s, peer, "192.0.2.2");
}

static void
mk_inner(struct rte_mbuf *m, unsigned iplen)
{
	uint8_t *f = (uint8_t *)rte_pktmbuf_append(m, 14 + iplen);
	struct rte_ipv4_hdr *ip = (void *)(f + 14);

	memset(f, 0, 14 + iplen);
	f[0] = 2; f[5] = 1; f[12] = 0x08;
	ip->version_ihl = 0x45; ip->total_length = rte_cpu_to_be_16(iplen);
	ip->time_to_live = 64; ip->next_proto_id = 17;
	inet_pton(AF_INET, "10.2.0.5", &ip->src_addr);
	inet_pton(AF_INET, "10.1.0.5", &ip->dst_addr);
	f[34] = 0x30; f[35] = 0x39; f[36] = 0x00; f[37] = 0x35;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
}

/* one enc + dec pass; best of `rep` runs (least noise) */
static int
measure(struct dpdk_priv *a, struct dpdk_priv *b, unsigned sz, int rep,
    double *enc, double *dec)
{
	*enc = *dec = 1e18;
	for (int r = 0; r < rep; r++) {
		uint64_t ce = 0, cd = 0;
		unsigned got = 0, ok = 0;

		for (unsigned bt = 0; bt < NPKT / BURST; bt++) {
			struct rte_mbuf *in[BURST], *out[BURST];
			uint16_t no = 0, nb = 0;
			uint64_t t;
			if (rte_pktmbuf_alloc_bulk(mp, in, BURST))
				return -1;
			for (int i = 0; i < BURST; i++)
				mk_inner(in[i], sz);
			t = rte_rdtsc_precise();
			esp_outbound(a, in, BURST, out, &no, &nb);
			ce += rte_rdtsc_precise() - t;
			for (int i = 0; i < no; i++) {
				uint8_t *f = (uint8_t *)rte_pktmbuf_prepend(out[i], 14);
				memset(f, 0, 14); f[12] = 8;
				espq[got++] = out[i];
			}
			for (int i = 0; i < BURST; i++)
				if (in[i]) rte_pktmbuf_free(in[i]);
		}
		for (unsigned i = 0; i < got; i += BURST) {
			struct rte_mbuf *o[BURST_SZ];
			uint16_t n = RTE_MIN((unsigned)BURST, got - i), k = 0;
			uint64_t t = rte_rdtsc_precise();
			esp_inbound(b, &espq[i], n, o, &k);
			cd += rte_rdtsc_precise() - t;
			ok += k;
			rte_pktmbuf_free_bulk(o, k);
		}
		if (got != NPKT || ok != got) {
			printf("  only %u/%u encrypted, %u decrypted\n", got, NPKT, ok);
			return -1;
		}
		*enc = RTE_MIN(*enc, (double)ce / got);
		*dec = RTE_MIN(*dec, (double)cd / got);
	}
	return 0;
}

static double
envf(const char *n, double def)
{
	const char *v = getenv(n);
	return v && *v ? atof(v) : def;
}

int
main(int argc, char **argv)
{
	char *ea[] = { "fwd_bench", "-l", "0", "--no-huge", "-m", "1024",
	    "--no-pci", "--no-telemetry", "--vdev=crypto_openssl0",
	    "--log-level=1", NULL };
	static const int tunnels[] = { 1, 65, 201 };
	struct rte_cryptodev_config cc;
	struct rte_cryptodev_qp_conf qc;
	struct dpdk_priv *a, *b;
	struct r2dp_sa r;
	double enc[3], dec[3];
	int check = 0, have = 1, fails = 0;
	unsigned sz = 64;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--check"))
			check = 1;
		else
			sz = (unsigned)atoi(argv[i]);
	}
	if (sz < 28 || sz > 1400) {
		fprintf(stderr, "fwd_bench: SIZE 28..1400\n");
		return 2;
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	if (rte_eal_init(10, ea) < 0 ||
	    (cdev = rte_cryptodev_get_dev_id("crypto_openssl0")) < 0) {
		if (getenv("R2DP_REQUIRE_DPDK")) { puts("DPDK setup FAILED"); return 1; }
		puts("SKIP: EAL/crypto_openssl"); return 77;
	}
	memset(&cc, 0, sizeof(cc)); cc.socket_id = SOCKET_ID_ANY; cc.nb_queue_pairs = 1;
	memset(&qc, 0, sizeof(qc)); qc.nb_descriptors = 2048;
	if (rte_cryptodev_configure(cdev, &cc) < 0 ||
	    rte_cryptodev_queue_pair_setup(cdev, 0, &qc, SOCKET_ID_ANY) < 0 ||
	    rte_cryptodev_start(cdev) < 0) { puts("cryptodev FAILED"); return 1; }
	mp = rte_pktmbuf_pool_create("bench_mb", NPKT * 2 + 4096, 256, 0,
	    RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	a = mk_priv("A"); b = mk_priv("B");
	if (!mp || !a || !b) { puts("setup FAILED"); return 1; }

	/* the measured tunnel: 10.2.0.0/24 -> 10.1.0.0/24 */
	mk_sa(&r, 0x5001, "192.0.2.1", "192.0.2.2"); r.dir = R2DP_DIR_OUT;
	if (sa_install(a, &r, key, 20, 0, 0)) { puts("SA FAILED"); return 1; }
	r.dir = R2DP_DIR_IN;
	if (sa_install(b, &r, key, 20, 0, 1) ||
	    add_sp(a, 1, R2DP_DIR_OUT, "10.2.0.0", "10.1.0.0", "192.0.2.1", "192.0.2.2") ||
	    add_sp(b, 1, R2DP_DIR_IN, "10.2.0.0", "10.1.0.0", "192.0.2.1", "192.0.2.2")) {
		puts("tunnel setup FAILED"); return 1;
	}
	printf("fwd_bench: %uB inner, %d-packet bursts, %d packets, best of 3\n",
	    sz, BURST, NPKT);
	for (int k = 0; k < 3; k++) {
		while (have < tunnels[k])
			if (add_tunnel(a, b, have++)) { puts("tunnel setup FAILED"); return 1; }
		if (measure(a, b, sz, 3, &enc[k], &dec[k])) { puts("FAIL measure"); return 1; }
		printf("  %3d tunnels: enc %7.0f cyc/pkt   dec %7.0f cyc/pkt\n",
		    tunnels[k], enc[k], dec[k]);
	}
	if (check) {
		double ms = envf("R2DP_BENCH_MAX_SCALE", 1.5);
		double mc = envf("R2DP_BENCH_MAX_CYC", 8000);
		double se = enc[2] / enc[0], sd = dec[2] / dec[0];
		printf("%s scaling 1->201 tunnels: enc x%.2f dec x%.2f (max x%.2f)\n",
		    se <= ms && sd <= ms ? "ok  " : "FAIL", se, sd, ms);
		fails += !(se <= ms && sd <= ms);
		if (mc > 0) {
			int ok = enc[0] <= mc && dec[0] <= mc;
			printf("%s 1 tunnel: enc %.0f dec %.0f cyc/pkt (max %.0f)\n",
			    ok ? "ok  " : "FAIL", enc[0], dec[0], mc);
			fails += !ok;
		}
	}
	free_priv(a); free_priv(b);
	rte_mempool_free(mp);
	rte_cryptodev_stop(cdev);
	rte_cryptodev_close(cdev);
	rte_eal_cleanup();
	return fails ? 1 : 0;
}

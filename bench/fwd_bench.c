/*
 * fwd_bench: single-core data-path cost of the production DPDK modules
 * (fwd/dpdk_esp.c over dpdk_sad.c/dpdk_spd.c) on a lookaside cryptodev:
 *
 *   inner frame -> esp_outbound (A: OUT policy + EGRESS SA)  "enc"
 *   ESP frame   -> esp_inbound  (B: INGRESS SA + IN policy)  "dec"
 *
 * For every inner IP size (default 64, 512, 1400 bytes) and tunnel count
 * (default 1, 65, 201; one carries the traffic, the rest are unrelated SAs
 * and policies on both sides) it runs one discarded warmup pass and then
 * N timed passes of NPKT packets in 32-packet bursts, reporting the median
 * cycles/pkt and the single-core Mpps that implies (TSC hz / cycles).
 * Building the test frames is outside the timed region.
 *
 *   fwd_bench [--check] [--json FILE|-] [--runs N] [--sizes a,b,..]
 *             [--tunnels a,b,..] [--pmd auto|openssl|aesni_mb] [--workers N]
 *
 * --workers N (N > 1): N lcores run the same enc/dec loop at once, each on
 * a tunnel it owns (dp_owner), sharing the cryptodev (one queue pair
 * each), the SAD and the policy snapshot; reports mean cycles/pkt and the
 * summed Mpps.  No --check gate in this mode.
 *
 * EAL runs with --no-huge.  --pmd auto (default) uses crypto_aesni_mb when
 * the ipsec_mb PMD is available and falls back to crypto_openssl.
 *
 * --check makes it a regression gate (meson `benchmark`, CI).  Only ratios
 * are gated, so it is stable across machines and runners:
 *   - scaling: per size, cycles at the largest tunnel count <=
 *     R2DP_BENCH_MAX_SCALE (default 1.5) x cycles at the smallest, for enc
 *     and dec -- exactly what a per-packet table scan breaks;
 *   - absolute sanity: smallest size, smallest tunnel count <=
 *     R2DP_BENCH_MAX_CYC (default 8000) cycles/pkt; 0 disables it
 *     (sanitizer builds).  Order-of-magnitude losses only.
 * Exit 77 (skip) without EAL/cryptodev unless R2DP_REQUIRE_DPDK=1.
 */
#include "dpdk_int.h"


#define NPKT 16384
#define BURST 32
#define MAXN 8
#define MAXRUNS 31

static uint8_t key[20] = { 9,8,7,6,5,4,3,2,1,0,1,2,3,4,5,6, 0xde,0xad,0xbe,0xef };
static struct rte_mempool *mp;
static int cdev = -1;
static struct rte_mbuf *espq[DP_MAX_WK][NPKT];

static struct dpdk_priv *
mk_priv(const char *tag)
{
	struct dpdk_priv *d = aligned_alloc(RTE_CACHE_LINE_SIZE, sizeof(*d));
	struct rte_ipsec_sad_conf sc;
	char n[32];

	if (!d)
		return NULL;
	memset(d, 0, sizeof(*d));
	d->nb_wk = 1;
	dp_wk_init(d, 0);
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
mk_inner(struct rte_mbuf *m, unsigned iplen, uint32_t src, uint32_t dst)
{
	uint8_t *f = (uint8_t *)rte_pktmbuf_append(m, 14 + iplen);
	struct rte_ipv4_hdr *ip = (void *)(f + 14);

	memset(f, 0, 14 + iplen);
	f[0] = 2; f[5] = 1; f[12] = 0x08;
	ip->version_ihl = 0x45; ip->total_length = rte_cpu_to_be_16(iplen);
	ip->time_to_live = 64; ip->next_proto_id = 17;
	ip->src_addr = src;
	ip->dst_addr = dst;
	f[34] = 0x30; f[35] = 0x39; f[36] = 0x00; f[37] = 0x35;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
}

static int
dblcmp(const void *x, const void *y)
{
	double a = *(const double *)x, b = *(const double *)y;

	return (a > b) - (a < b);
}

/* One untimed warmup pass, then `rep` timed enc + dec passes; the median
 * of each (robust against a preempted run in either direction). */
/* inner addresses of the traffic each worker sends (wire order) */
static uint32_t flow_src[DP_MAX_WK], flow_dst[DP_MAX_WK];

static int
measure(struct dpdk_priv *a, struct dpdk_priv *b, unsigned w, unsigned sz,
    int rep, double *enc, double *dec)
{
	double re[MAXRUNS], rd[MAXRUNS];

	for (int r = -1; r < rep; r++) {
		uint64_t ce = 0, cd = 0;
		unsigned got = 0, ok = 0;

		for (unsigned bt = 0; bt < NPKT / BURST; bt++) {
			struct rte_mbuf *in[BURST], *out[BURST];
			uint16_t no = 0, nb = 0;
			uint64_t t;
			if (rte_pktmbuf_alloc_bulk(mp, in, BURST))
				return -1;
			for (int i = 0; i < BURST; i++)
				mk_inner(in[i], sz, flow_src[w], flow_dst[w]);
			t = rte_rdtsc_precise();
			esp_outbound(&a->wk[w], in, BURST, out, &no, &nb);
			ce += rte_rdtsc_precise() - t;
			for (int i = 0; i < no; i++) {
				uint8_t *f = (uint8_t *)rte_pktmbuf_prepend(out[i], 14);
				memset(f, 0, 14); f[12] = 8;
				espq[w][got++] = out[i];
			}
			for (int i = 0; i < BURST; i++)
				if (in[i]) rte_pktmbuf_free(in[i]);
		}
		for (unsigned i = 0; i < got; i += BURST) {
			struct rte_mbuf *o[BURST_SZ];
			uint16_t n = RTE_MIN((unsigned)BURST, got - i), k = 0;
			uint64_t t = rte_rdtsc_precise();
			esp_inbound(&b->wk[w], &espq[w][i], n, o, &k);
			cd += rte_rdtsc_precise() - t;
			ok += k;
			rte_pktmbuf_free_bulk(o, k);
		}
		if (got != NPKT || ok != got) {
			printf("  only %u/%u encrypted, %u decrypted\n", got, NPKT, ok);
			return -1;
		}
		if (r < 0)
			continue;           /* warmup */
		re[r] = (double)ce / got;
		rd[r] = (double)cd / got;
	}
	qsort(re, rep, sizeof(re[0]), dblcmp);
	qsort(rd, rep, sizeof(rd[0]), dblcmp);
	*enc = rep & 1 ? re[rep / 2] : (re[rep / 2 - 1] + re[rep / 2]) / 2;
	*dec = rep & 1 ? rd[rep / 2] : (rd[rep / 2 - 1] + rd[rep / 2]) / 2;
	return 0;
}

static double
envf(const char *n, double def)
{
	const char *v = getenv(n);
	return v && *v ? atof(v) : def;
}

/* "64,512,1400" -> v[]; returns the count, -1 on junk or overflow */
static int
parse_list(const char *s, int *v, int lo, int hi)
{
	int n = 0;

	while (*s) {
		char *e;
		long x = strtol(s, &e, 10);
		if (e == s || x < lo || x > hi || n == MAXN)
			return -1;
		v[n++] = (int)x;
		s = *e == ',' ? e + 1 : e;
		if (*e && *e != ',')
			return -1;
	}
	return n;
}

/* Prefer AES-NI multi-buffer, else OpenSSL.  Returns the cryptodev id. */
static int
pick_cdev(const char *pmd, const char **name)
{
	int id;

	if (strcmp(pmd, "openssl") &&
	    (rte_eal_hotplug_add("vdev", "crypto_aesni_mb0", "") == 0 ||
	     rte_cryptodev_get_dev_id("crypto_aesni_mb0") >= 0) &&
	    (id = rte_cryptodev_get_dev_id("crypto_aesni_mb0")) >= 0) {
		*name = "aesni_mb";
		return id;
	}
	if (!strcmp(pmd, "aesni_mb"))
		return -1;
	*name = "openssl";
	return rte_cryptodev_get_dev_id("crypto_openssl0");
}

/* ---- multi-worker mode (--workers N) ---------------------------------- */
static struct dpdk_priv *mt_a, *mt_b;
static unsigned mt_sz;
static int mt_runs, mt_err;
static double mt_enc[DP_MAX_WK], mt_dec[DP_MAX_WK];
static volatile int mt_go;

static int
mt_worker(void *arg)
{
	unsigned w = (unsigned)(uintptr_t)arg;

	while (!mt_go)
		rte_pause();
	if (measure(mt_a, mt_b, w, mt_sz, mt_runs, &mt_enc[w], &mt_dec[w]))
		mt_err = 1;
	return 0;
}

/* One tunnel per worker, chosen so that worker owns it (dp_owner), each
 * worker encrypting and then decrypting its own traffic at the same time
 * as the others.  Aggregate Mpps = sum of the per-worker rates. */
static int
mt_tunnels(struct dpdk_priv *a, struct dpdk_priv *b, unsigned nw)
{
	uint32_t us, peer;
	unsigned have = 0;

	inet_pton(AF_INET, "192.0.2.1", &us);
	for (unsigned p = 1; p < 250 && have != (1u << nw) - 1; p++) {
		char ps[32], s[32], t[32];
		struct r2dp_sa r;
		unsigned w;

		snprintf(ps, sizeof(ps), "203.0.113.%u", p);
		inet_pton(AF_INET, ps, &peer);
		w = dp_owner(nw, us, peer);
		if (have & (1u << w))
			continue;
		have |= 1u << w;
		snprintf(s, sizeof(s), "172.20.%u.0", w);
		snprintf(t, sizeof(t), "172.21.%u.0", w);
		mk_sa(&r, 0x6000 + w, "192.0.2.1", ps); r.dir = R2DP_DIR_OUT;
		if (sa_install(a, &r, key, 20, 0, 0)) return -1;
		r.dir = R2DP_DIR_IN;
		if (sa_install(b, &r, key, 20, 0, 1) ||
		    add_sp(a, 100 + w, R2DP_DIR_OUT, s, t, "192.0.2.1", ps) ||
		    add_sp(b, 100 + w, R2DP_DIR_IN, s, t, "192.0.2.1", ps))
			return -1;
		snprintf(s, sizeof(s), "172.20.%u.5", w);
		snprintf(t, sizeof(t), "172.21.%u.5", w);
		inet_pton(AF_INET, s, &flow_src[w]);
		inet_pton(AF_INET, t, &flow_dst[w]);
	}
	return have == (1u << nw) - 1 ? 0 : -1;
}

static int
mt_run(struct dpdk_priv *a, struct dpdk_priv *b, unsigned nw, const int *sizes,
    int nsz, int runs, double hz, FILE *jf, const char *pmdname)
{
	printf("  size workers  enc cyc/pkt  enc Mpps (sum)  dec cyc/pkt  "
	    "dec Mpps (sum)\n");
	if (jf)
		fprintf(jf, "{\"bench\":\"fwd_bench\",\"pmd\":\"%s\",\"workers\":%u,"
		    "\"burst\":%d,\"packets\":%d,\"runs\":%d,\"tsc_hz\":%.0f,"
		    "\"results\":[", pmdname, nw, BURST, NPKT, runs, hz);
	for (int z = 0; z < nsz; z++) {
		unsigned w = 0, lc;
		double ce = 0, cd = 0, me = 0, md = 0;

		mt_a = a; mt_b = b; mt_sz = (unsigned)sizes[z]; mt_runs = runs;
		mt_go = 0;
		RTE_LCORE_FOREACH_WORKER(lc) {
			if (w == nw)
				break;
			rte_eal_remote_launch(mt_worker, (void *)(uintptr_t)w++, lc);
		}
		mt_go = 1;
		rte_eal_mp_wait_lcore();
		if (mt_err) { puts("FAIL measure"); return -1; }
		for (w = 0; w < nw; w++) {
			ce += mt_enc[w] / nw; cd += mt_dec[w] / nw;
			me += hz / mt_enc[w] / 1e6; md += hz / mt_dec[w] / 1e6;
		}
		printf("  %4d %7u  %11.0f  %14.2f  %11.0f  %14.2f\n", sizes[z], nw,
		    ce, me, cd, md);
		if (jf)
			fprintf(jf, "%s\n {\"size\":%d,\"workers\":%u,"
			    "\"enc_cyc_pkt\":%.1f,\"enc_mpps\":%.3f,"
			    "\"dec_cyc_pkt\":%.1f,\"dec_mpps\":%.3f}", z ? "," : "",
			    sizes[z], nw, ce, me, cd, md);
	}
	if (jf)
		fprintf(jf, "\n]}\n");
	return 0;
}

static void
usage(void)
{
	fprintf(stderr, "usage: fwd_bench [--check] [--json FILE|-] [--runs N] "
	    "[--sizes 64,512,1400] [--tunnels 1,65,201] "
	    "[--pmd auto|openssl|aesni_mb] [--workers N]\n");
}

int
main(int argc, char **argv)
{
	char lcl[16] = "0";
	char *ea[] = { "fwd_bench", "-l", lcl, "--no-huge", "-m", "1024",
	    "--no-pci", "--no-telemetry", "--vdev=crypto_openssl0",
	    "--log-level=1", NULL };
	int sizes[MAXN] = { 64, 512, 1400 }, tunnels[MAXN] = { 1, 65, 201 };
	int nsz = 3, ntun = 3, runs = 5, check = 0, have = 1, fails = 0;
	int nw = 1;
	double enc[MAXN][MAXN], dec[MAXN][MAXN], hz;
	const char *json = NULL, *pmd = "auto", *pmdname = "?";
	struct rte_cryptodev_config cc;
	struct rte_cryptodev_qp_conf qc;
	struct dpdk_priv *a, *b;
	struct r2dp_sa r;

	for (int i = 1; i < argc; i++) {
		const char *v = i + 1 < argc ? argv[i + 1] : NULL;
		if (!strcmp(argv[i], "--check"))
			check = 1;
		else if (!strcmp(argv[i], "--json") && v)
			json = argv[++i];
		else if (!strcmp(argv[i], "--runs") && v)
			runs = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--sizes") && v)
			nsz = parse_list(argv[++i], sizes, 28, 1400);
		else if (!strcmp(argv[i], "--tunnels") && v)
			ntun = parse_list(argv[++i], tunnels, 1, MAX_SA / 2 - 1);
		else if (!strcmp(argv[i], "--workers") && v)
			nw = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--pmd") && v)
			pmd = argv[++i];
		else {
			usage();
			return 2;
		}
	}
	if (nsz < 1 || ntun < 1 || runs < 1 || runs > MAXRUNS || nw < 1 ||
	    nw > DP_MAX_WK ||
	    (strcmp(pmd, "auto") && strcmp(pmd, "openssl") &&
	     strcmp(pmd, "aesni_mb"))) {
		usage();
		return 2;
	}
	for (int k = 1; k < ntun; k++)
		if (tunnels[k] <= tunnels[k - 1]) {
			fprintf(stderr, "fwd_bench: --tunnels must increase\n");
			return 2;
		}
	if (nw > 1)
		snprintf(lcl, sizeof(lcl), "0-%d", nw);
	setvbuf(stdout, NULL, _IONBF, 0);
	if (rte_eal_init(10, ea) < 0 || (cdev = pick_cdev(pmd, &pmdname)) < 0) {
		if (getenv("R2DP_REQUIRE_DPDK")) { puts("DPDK setup FAILED"); return 1; }
		puts("SKIP: EAL/cryptodev"); return 77;
	}
	hz = (double)rte_get_tsc_hz();
	memset(&cc, 0, sizeof(cc)); cc.socket_id = SOCKET_ID_ANY;
	cc.nb_queue_pairs = (uint16_t)nw;
	memset(&qc, 0, sizeof(qc)); qc.nb_descriptors = 2048;
	if (rte_cryptodev_configure(cdev, &cc) < 0) { puts("cryptodev FAILED"); return 1; }
	for (int q = 0; q < nw; q++)
		if (rte_cryptodev_queue_pair_setup(cdev, (uint16_t)q, &qc,
		    SOCKET_ID_ANY) < 0) { puts("cryptodev qp FAILED"); return 1; }
	if (rte_cryptodev_start(cdev) < 0) { puts("cryptodev FAILED"); return 1; }
	mp = rte_pktmbuf_pool_create("bench_mb", nw * (NPKT + 4 * BURST) + 4096,
	    256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	a = mk_priv("A"); b = mk_priv("B");
	if (!mp || !a || !b) { puts("setup FAILED"); return 1; }
	inet_pton(AF_INET, "10.2.0.5", &flow_src[0]);
	inet_pton(AF_INET, "10.1.0.5", &flow_dst[0]);
	if (nw > 1) {
		FILE *jf = NULL;
		int rc;

		if (rte_lcore_count() < (unsigned)nw + 1) { puts("lcores FAILED"); return 1; }
		a->nb_wk = b->nb_wk = (unsigned)nw;   /* before any SA: owners */
		for (int w = 0; w < nw; w++) {
			dp_wk_init(a, (unsigned)w);
			dp_wk_init(b, (unsigned)w);
		}
		if (mt_tunnels(a, b, (unsigned)nw)) { puts("tunnel setup FAILED"); return 1; }
		printf("fwd_bench: crypto_%s, %d workers, %d-packet bursts, %d "
		    "packets/worker, warmup + median of %d, TSC %.2f GHz\n",
		    pmdname, nw, BURST, NPKT, runs, hz / 1e9);
		if (json && !(jf = strcmp(json, "-") ? fopen(json, "w") : stdout)) {
			perror(json); return 1;
		}
		rc = mt_run(a, b, (unsigned)nw, sizes, nsz, runs, hz, jf, pmdname);
		if (jf && jf != stdout)
			fclose(jf);
		free_priv(a); free_priv(b);
		rte_mempool_free(mp);
		rte_cryptodev_stop(cdev);
		rte_cryptodev_close(cdev);
		rte_eal_cleanup();
		return rc ? 1 : 0;
	}

	/* the measured tunnel: 10.2.0.0/24 -> 10.1.0.0/24 */
	mk_sa(&r, 0x5001, "192.0.2.1", "192.0.2.2"); r.dir = R2DP_DIR_OUT;
	if (sa_install(a, &r, key, 20, 0, 0)) { puts("SA FAILED"); return 1; }
	r.dir = R2DP_DIR_IN;
	if (sa_install(b, &r, key, 20, 0, 1) ||
	    add_sp(a, 1, R2DP_DIR_OUT, "10.2.0.0", "10.1.0.0", "192.0.2.1", "192.0.2.2") ||
	    add_sp(b, 1, R2DP_DIR_IN, "10.2.0.0", "10.1.0.0", "192.0.2.1", "192.0.2.2")) {
		puts("tunnel setup FAILED"); return 1;
	}
	printf("fwd_bench: crypto_%s, %d-packet bursts, %d packets, "
	    "warmup + median of %d, TSC %.2f GHz\n", pmdname, BURST, NPKT, runs,
	    hz / 1e9);
	printf("  size tunnels   enc cyc/pkt  enc Mpps   dec cyc/pkt  dec Mpps\n");
	for (int k = 0; k < ntun; k++) {
		while (have < tunnels[k])
			if (add_tunnel(a, b, have++)) { puts("tunnel setup FAILED"); return 1; }
		for (int z = 0; z < nsz; z++) {
			if (measure(a, b, 0, (unsigned)sizes[z], runs, &enc[z][k], &dec[z][k])) {
				puts("FAIL measure"); return 1;
			}
			printf("  %4d %7d   %11.0f  %8.2f   %11.0f  %8.2f\n",
			    sizes[z], tunnels[k], enc[z][k], hz / enc[z][k] / 1e6,
			    dec[z][k], hz / dec[z][k] / 1e6);
		}
	}
	if (check) {
		double ms = envf("R2DP_BENCH_MAX_SCALE", 1.5);
		double mc = envf("R2DP_BENCH_MAX_CYC", 8000);
		int t = ntun - 1;
		for (int z = 0; z < nsz && t > 0; z++) {
			double se = enc[z][t] / enc[z][0], sd = dec[z][t] / dec[z][0];
			int ok = se <= ms && sd <= ms;
			printf("%s %4dB scaling %d->%d tunnels: enc x%.2f dec x%.2f (max x%.2f)\n",
			    ok ? "ok  " : "FAIL", sizes[z], tunnels[0], tunnels[t],
			    se, sd, ms);
			fails += !ok;
		}
		if (mc > 0) {
			int ok = enc[0][0] <= mc && dec[0][0] <= mc;
			printf("%s %dB, %d tunnel(s): enc %.0f dec %.0f cyc/pkt (max %.0f)\n",
			    ok ? "ok  " : "FAIL", sizes[0], tunnels[0], enc[0][0],
			    dec[0][0], mc);
			fails += !ok;
		}
	}
	if (json) {
		FILE *f = strcmp(json, "-") ? fopen(json, "w") : stdout;
		if (!f) { perror(json); return 1; }
		fprintf(f, "{\"bench\":\"fwd_bench\",\"pmd\":\"%s\",\"burst\":%d,"
		    "\"packets\":%d,\"runs\":%d,\"tsc_hz\":%.0f,\"results\":[",
		    pmdname, BURST, NPKT, runs, hz);
		for (int k = 0, c = 0; k < ntun; k++)
			for (int z = 0; z < nsz; z++, c++)
				fprintf(f, "%s\n {\"size\":%d,\"tunnels\":%d,"
				    "\"enc_cyc_pkt\":%.1f,\"enc_mpps\":%.3f,"
				    "\"dec_cyc_pkt\":%.1f,\"dec_mpps\":%.3f}",
				    c ? "," : "", sizes[z], tunnels[k],
				    enc[z][k], hz / enc[z][k] / 1e6,
				    dec[z][k], hz / dec[z][k] / 1e6);
		fprintf(f, "\n],\"check_failures\":%d}\n", fails);
		if (f != stdout)
			fclose(f);
	}
	free_priv(a); free_priv(b);
	rte_mempool_free(mp);
	rte_cryptodev_stop(cdev);
	rte_cryptodev_close(cdev);
	rte_eal_cleanup();
	return fails ? 1 : 0;
}

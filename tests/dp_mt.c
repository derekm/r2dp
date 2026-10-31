/*
 * dp_mt: multi-worker safety of the production DPDK data path.
 *
 * NW workers run esp_outbound / esp_inbound at the same time on shared
 * forwarders (A egress, B ingress) with NT tunnels, every worker offered
 * packets for every tunnel.  Each SA must be processed by exactly one
 * worker (dp_sa.owner):
 *   - outbound: a worker encrypts only for tunnels it owns, the rest are
 *     dropped as `steer`; ESP sequence numbers are unique per SPI and
 *     gapless (no SA was advanced by two lcores);
 *   - inbound: every ESP datagram, offered to every worker, is accepted
 *     exactly once (by its owner) and its copies elsewhere drop as `steer`;
 *     offered again, nothing is accepted (replay window has one writer).
 * Exit 77 (skip) without EAL/crypto_openssl or lcores unless
 * R2DP_REQUIRE_DPDK=1.
 */
#include "dpdk_int.h"

#define NW     3
#define NT     12
#define ROUNDS 8
#define BURST  32
#define NOUT   (ROUNDS * BURST)

static int fails;
#define CHECK(c, m) do { if (c) printf("ok   %s\n", m); \
	else { printf("FAIL %s\n", m); fails++; } } while (0)

static uint8_t key[20] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 0xca,0xfe,0xba,0xbe };
static struct rte_mempool *mp;
static int cdev = -1;
static struct dpdk_priv *A, *B;

/* per-worker results */
static struct rte_mbuf *esp_out[NW][NOUT];
static uint16_t n_out[NW];
static struct rte_mbuf *esp_in[NW][NW * NOUT];
static unsigned n_acc[NW];
static volatile int go;

static struct dpdk_priv *
mk_priv(const char *tag)
{
	struct dpdk_priv *d = aligned_alloc(RTE_CACHE_LINE_SIZE, sizeof(*d));
	struct rte_ipsec_sad_conf sc;
	char n[32];

	if (!d)
		return NULL;
	memset(d, 0, sizeof(*d));
	d->nb_wk = NW;
	for (unsigned i = 0; i <= NW; i++)
		dp_wk_init(d, i);
	d->cdev_id = (uint8_t)cdev;
	d->have_cdev = 1;
	snprintf(n, sizeof(n), "%s_sess", tag);
	d->sess_mp = rte_cryptodev_sym_session_pool_create(n, 2 * NT + 8,
	    rte_cryptodev_sym_get_private_session_size(d->cdev_id), 0, 0,
	    SOCKET_ID_ANY);
	snprintf(n, sizeof(n), "%s_cop", tag);
	d->cop_mp = rte_crypto_op_pool_create(n, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
	    4096, 0, sizeof(struct rte_crypto_op) +
	    sizeof(struct rte_crypto_sym_op) + R2DP_GCM_IV_LEN, SOCKET_ID_ANY);
	memset(&sc, 0, sizeof(sc));
	sc.socket_id = SOCKET_ID_ANY;
	sc.max_sa[RTE_IPSEC_SAD_SPI_DIP] = 2 * NT + 8;
	sc.flags = RTE_IPSEC_SAD_FLAG_RW_CONCURRENCY;
	snprintf(n, sizeof(n), "%s_sad", tag);
	d->sad = rte_ipsec_sad_create(n, &sc);
	if (!d->sess_mp || !d->cop_mp || !d->sad)
		return NULL;
	rte_spinlock_init(&d->lock);
	return d;
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

static int
add_tunnel(int k)
{
	char t[32], peer[32];
	struct r2dp_sa r;

	snprintf(t, sizeof(t), "172.17.%d.0", k);
	snprintf(peer, sizeof(peer), "198.51.100.%d", k + 1);
	memset(&r, 0, sizeof(r));
	r.proto = R2DP_PROTO_ESP; r.mode = R2DP_MODE_TUNNEL;
	r.enc = R2DP_ENCR_AES_GCM_16; r.spi = htonl(0x7000 + k);
	r.enckeylen = 20; r.wsize = 64;
	r.src.family = r.dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "192.0.2.1", r.src.addr);
	inet_pton(AF_INET, peer, r.dst.addr);
	r.dir = R2DP_DIR_OUT;
	if (sa_install(A, &r, key, 20, 0, 0))
		return -1;
	r.dir = R2DP_DIR_IN;
	if (sa_install(B, &r, key, 20, 0, 1))
		return -1;
	if (add_sp(A, k + 1, R2DP_DIR_OUT, "10.2.0.0", t, "192.0.2.1", peer))
		return -1;
	return add_sp(B, k + 1, R2DP_DIR_IN, "10.2.0.0", t, "192.0.2.1", peer);
}

static void
mk_inner(struct rte_mbuf *m, int k, uint16_t id)
{
	uint8_t *f = (uint8_t *)rte_pktmbuf_append(m, 14 + 64);
	struct rte_ipv4_hdr *ip;
	char dst[32];

	if (f == NULL)
		return;
	ip = (void *)(f + 14);
	memset(f, 0, 14 + 64);
	f[0] = 2; f[5] = 1; f[12] = 0x08;
	ip->version_ihl = 0x45; ip->total_length = rte_cpu_to_be_16(64);
	ip->time_to_live = 64; ip->next_proto_id = 17;
	ip->packet_id = rte_cpu_to_be_16(id);
	snprintf(dst, sizeof(dst), "172.17.%d.5", k);
	inet_pton(AF_INET, "10.2.0.5", &ip->src_addr);
	inet_pton(AF_INET, dst, &ip->dst_addr);
	f[34] = 0x30; f[35] = 0x39; f[36] = 0x00; f[37] = 0x35;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
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

static unsigned
self_id(void)
{
	unsigned i = 0, lc, me = rte_lcore_id();

	RTE_LCORE_FOREACH_WORKER(lc) {
		if (lc == me)
			return i;
		i++;
	}
	return 0;
}

static int
enc_worker(void *arg)
{
	unsigned w = self_id();

	(void)arg;
	while (!go)
		rte_pause();
	for (int r = 0; r < ROUNDS; r++) {
		struct rte_mbuf *in[BURST], *out[BURST];
		uint16_t no = 0, nb = 0;

		if (rte_pktmbuf_alloc_bulk(mp, in, BURST))
			return -1;
		for (int j = 0; j < BURST; j++)
			mk_inner(in[j], (r * BURST + j + (int)w) % NT,
			    (uint16_t)(w << 12 | (unsigned)(r * BURST + j)));
		esp_outbound(&A->wk[w], in, BURST, out, &no, &nb);
		for (int j = 0; j < BURST; j++)
			if (in[j])
				rte_pktmbuf_free(in[j]);
		for (uint16_t j = 0; j < no; j++)
			esp_out[w][n_out[w]++] = out[j];
	}
	return 0;
}

static int
dec_worker(void *arg)
{
	unsigned w = self_id(), n = *(unsigned *)arg;

	while (!go)
		rte_pause();
	for (unsigned i = 0; i < n; i += BURST) {
		struct rte_mbuf *o[BURST_SZ];
		uint16_t c = (uint16_t)RTE_MIN((unsigned)BURST, n - i), k = 0;

		esp_inbound(&B->wk[w], &esp_in[w][i], c, o, &k);
		n_acc[w] += k;
		rte_pktmbuf_free_bulk(o, k);
	}
	return 0;
}

/* Offer every worker its own copy of all ESP datagrams, concurrently. */
static unsigned
offer_all(struct rte_mbuf **all, unsigned nall)
{
	unsigned lc, tot = 0;

	go = 0;
	for (unsigned w = 0; w < NW; w++) {
		n_acc[w] = 0;
		for (unsigned i = 0; i < nall; i++)
			esp_in[w][i] = rte_pktmbuf_copy(all[i], mp, 0, UINT32_MAX);
	}
	RTE_LCORE_FOREACH_WORKER(lc)
		rte_eal_remote_launch(dec_worker, &nall, lc);
	go = 1;
	rte_eal_mp_wait_lcore();
	for (unsigned w = 0; w < NW; w++)
		tot += n_acc[w];
	return tot;
}

static uint64_t
steer(struct dpdk_priv *d)
{
	uint64_t s = 0;

	for (unsigned w = 0; w < NW; w++)
		s += d->wk[w].n_dropr[DR_STEER];
	return s;
}

int
main(void)
{
	char *ea[] = { "dp_mt", "-l", "0-3", "--no-huge", "--no-pci", "-m", "512",
	    "--no-telemetry", "--vdev=crypto_openssl0", "--log-level=1", NULL };
	struct rte_cryptodev_config cc;
	struct rte_cryptodev_qp_conf qc;
	static struct rte_mbuf *all[NW * NOUT];
	static uint32_t seen[NT][NW * NOUT + 2];
	unsigned nall = 0, lc, owned[NW] = { 0 }, dup = 0, gap = 0, mixed = 0;
	unsigned owners_used = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (rte_eal_init(10, ea) < 0 || rte_lcore_count() < NW + 1 ||
	    (cdev = rte_cryptodev_get_dev_id("crypto_openssl0")) < 0) {
		if (getenv("R2DP_REQUIRE_DPDK")) { puts("DPDK setup FAILED"); return 1; }
		puts("SKIP: EAL/crypto_openssl/lcores"); return 77;
	}
	memset(&cc, 0, sizeof(cc)); cc.socket_id = SOCKET_ID_ANY;
	cc.nb_queue_pairs = NW;
	memset(&qc, 0, sizeof(qc)); qc.nb_descriptors = 512;
	if (rte_cryptodev_configure(cdev, &cc) < 0) { puts("cryptodev FAILED"); return 1; }
	for (uint16_t q = 0; q < NW; q++)
		if (rte_cryptodev_queue_pair_setup(cdev, q, &qc, SOCKET_ID_ANY) < 0) {
			puts("qp FAILED"); return 1;
		}
	if (rte_cryptodev_start(cdev) < 0) { puts("cryptodev FAILED"); return 1; }
	mp = rte_pktmbuf_pool_create("dp_mt_mb", 16384, 0, 0,
	    RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	A = mk_priv("A"); B = mk_priv("B");
	if (!mp || !A || !B) { puts("setup FAILED"); return 1; }
	for (int k = 0; k < NT; k++)
		if (add_tunnel(k)) { puts("tunnel setup FAILED"); return 1; }
	for (int i = 0; i < MAX_SA; i++)
		if (A->sa_tab[i].used)
			owners_used |= 1u << A->sa_tab[i].owner;
	CHECK(owners_used == (1u << NW) - 1, "tunnels spread over every worker");

	/* 1. concurrent encrypt: every worker offered every tunnel */
	go = 0;
	RTE_LCORE_FOREACH_WORKER(lc)
		rte_eal_remote_launch(enc_worker, NULL, lc);
	go = 1;
	rte_eal_mp_wait_lcore();
	for (unsigned w = 0; w < NW; w++)
		for (unsigned i = 0; i < n_out[w]; i++) {
			const uint8_t *p = rte_pktmbuf_mtod(esp_out[w][i], const uint8_t *);
			uint32_t spi, seq;
			int k;

			memcpy(&spi, p + 20, 4); memcpy(&seq, p + 24, 4);
			k = (int)(ntohl(spi) - 0x7000);
			seq = ntohl(seq);
			if (k < 0 || k >= NT || seq >= RTE_DIM(seen[0])) { dup++; continue; }
			if (seen[k][seq]++)
				dup++;
			if (seen[k][0] == 0)
				seen[k][0] = w + 1;          /* first worker on this SA */
			else if (seen[k][0] != w + 1)
				mixed++;
			owned[w]++;
			all[nall++] = esp_out[w][i];
		}
	for (int k = 0; k < NT; k++) {
		unsigned n = 0;
		for (unsigned s = 1; s < RTE_DIM(seen[0]); s++)
			n += seen[k][s] != 0;
		for (unsigned s = 1; s <= n; s++)
			gap += seen[k][s] != 1;           /* 1..n each exactly once */
	}
	CHECK(nall > 0 && dup == 0 && gap == 0,
	    "outbound: ESP sequence numbers unique and gapless per SPI");
	CHECK(mixed == 0, "outbound: each SA encrypted by one worker only");
	CHECK(nall + steer(A) == NW * NOUT,
	    "outbound: non-owner packets dropped as steer, none lost");
	printf("     encrypted per worker: %u %u %u, steered %llu\n", owned[0],
	    owned[1], owned[2], (unsigned long long)steer(A));

	/* 2. concurrent decrypt: all datagrams offered to every worker */
	for (unsigned i = 0; i < nall; i++) {
		uint8_t *f = (uint8_t *)rte_pktmbuf_prepend(all[i], 14);
		if (f) { memset(f, 0, 14); f[12] = 8; }
	}
	/* dispatcher steering (batched): every ESP frame to its SA's owner,
	 * every protected inner frame to its egress SA's owner, a non-ESP
	 * outer frame to worker 0 */
	{
		unsigned bad = 0;
		for (unsigned i = 0; i < nall; i += BURST_SZ) {
			uint16_t c = (uint16_t)RTE_MIN((unsigned)BURST_SZ, nall - i);
			uint8_t t[BURST_SZ];

			dp_steer_outer(B, &all[i], c, t);
			for (uint16_t j = 0; j < c; j++) {
				const uint8_t *p = rte_pktmbuf_mtod(all[i + j],
				    const uint8_t *);
				uint32_t spi;
				memcpy(&spi, p + 14 + 20, 4);
				if (t[j] + 1u != seen[ntohl(spi) - 0x7000][0])
					bad++;
			}
		}
		CHECK(bad == 0, "steer: ESP frames go to the owner of their SA");
		bad = 0;
		{
			struct rte_mbuf *in[BURST_SZ];
			uint8_t t[BURST_SZ];
			if (rte_pktmbuf_alloc_bulk(mp, in, BURST_SZ) == 0) {
				for (int j = 0; j < BURST_SZ; j++)
					mk_inner(in[j], (j / 3) % NT, (uint16_t)j);
				dp_steer_inner(A, in, BURST_SZ, t);
				for (int j = 0; j < BURST_SZ; j++)
					if (t[j] + 1u != seen[(j / 3) % NT][0])
						bad++;
				/* an ARP-looking frame on the outer side: worker 0 */
				rte_pktmbuf_mtod(in[0], uint8_t *)[12] = 0x08;
				rte_pktmbuf_mtod(in[0], uint8_t *)[13] = 0x06;
				dp_steer_outer(B, in, 1, t);
				bad += t[0] != 0;
				rte_pktmbuf_free_bulk(in, BURST_SZ);
			} else
				bad++;
		}
		CHECK(bad == 0, "steer: inner frames go to their egress SA's owner");
	}
	{
		unsigned acc = offer_all(all, nall);
		CHECK(acc == nall, "inbound: every datagram accepted exactly once");
		CHECK(steer(B) == (uint64_t)nall * (NW - 1),
		    "inbound: copies at non-owners dropped as steer");
		acc = offer_all(all, nall);
		CHECK(acc == 0, "inbound: replayed datagrams accepted by nobody");
	}
	for (unsigned i = 0; i < nall; i++)
		rte_pktmbuf_free(all[i]);
	free_priv(A); free_priv(B);
	rte_mempool_free(mp);
	rte_cryptodev_stop(cdev);
	rte_cryptodev_close(cdev);
	rte_eal_cleanup();
	if (fails) { printf("dp_mt: %d failures\n", fails); return 1; }
	puts("dp_mt: OK");
	return 0;
}

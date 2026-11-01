/*
 * dp_grow: SA/SP table growth under traffic, through the production data
 * path (crypto_openssl vdev, ASan in CI's sanitizer lane).
 *
 * Forwarder A (OUT policies + egress SAs) and B (IN policies + ingress
 * SAs) start empty -- no preallocated SA/SP slots, a 64-entry SAD and a
 * 64-session pool -- and are grown to NT tunnels (default 10000) while a
 * worker lcore keeps sending inner packets for random already-installed
 * tunnels A -> encrypt -> B -> decrypt.  Every one must come out
 * byte-identical: growth of the SA/SP chunks, the inbound SAD, the
 * session pools and the policy snapshot never drops a packet of a live
 * tunnel.  Then allocation failure is injected: installs beyond the free
 * slots are refused (-ENOMEM), every existing tunnel keeps forwarding,
 * and installs succeed again once memory is back.
 */
#include <time.h>

#include "dpdk_int.h"

static int fails;
#define CHECK(c, m) do { if (c) printf("ok   %s\n", m); \
	else { printf("FAIL %s\n", m); fails++; } } while (0)

static uint8_t key[20] = { 9,8,7,6,5,4,3,2,1,0,1,2,3,4,5,6, 0xde,0xad,0xbe,0xef };
static struct rte_mempool *mp;
static int cdev = -1;
static struct dpdk_priv *A, *B;
static uint32_t ready;              /* tunnels [0, ready) installed */
static uint32_t lo;                 /* ... and not yet deleted below lo */
static volatile int stop;
static uint64_t n_ok, n_bad;

static double
now_s(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static struct dpdk_priv *
mk_priv(const char *tag)
{
	struct dpdk_priv *d = aligned_alloc(RTE_CACHE_LINE_SIZE, sizeof(*d));
	struct rte_ipsec_sad_conf sc;
	char n[32];
	size_t rsz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);

	if (!d)
		return NULL;
	memset(d, 0, sizeof(*d));
	d->nb_wk = 1;
	dp_wk_init(d, 0);
	d->cdev_id = (uint8_t)cdev;
	d->have_cdev = 1;
	d->spin_max = 100000;
	d->rcu = rte_zmalloc(NULL, rsz, RTE_CACHE_LINE_SIZE);
	if (!d->rcu || rte_rcu_qsbr_init(d->rcu, RTE_MAX_LCORE))
		return NULL;
	snprintf(n, sizeof(n), "%s_sess", tag);
	d->sess_mp = rte_cryptodev_sym_session_pool_create(n, 64,
	    rte_cryptodev_sym_get_private_session_size(d->cdev_id), 0, 0,
	    SOCKET_ID_ANY);
	snprintf(n, sizeof(n), "%s_cop", tag);
	d->cop_mp = rte_crypto_op_pool_create(n, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
	    256, 0, sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op) +
	    R2DP_GCM_IV_LEN, SOCKET_ID_ANY);
	memset(&sc, 0, sizeof(sc));
	sc.socket_id = SOCKET_ID_ANY;
	sc.max_sa[RTE_IPSEC_SAD_SPI_DIP] = 64;
	sc.flags = RTE_IPSEC_SAD_FLAG_RW_CONCURRENCY;
	snprintf(n, sizeof(n), "%s_sad", tag);
	d->sad = rte_ipsec_sad_create(n, &sc);
	d->sad_cap = 64;                    /* grows from here */
	if (!d->sess_mp || !d->cop_mp || !d->sad)
		return NULL;
	snprintf(n, sizeof(n), "%s_nh", tag);
	if (r2dp_nh_init(&d->nh, n, 8, d->rcu, SOCKET_ID_ANY))
		return NULL;
	rte_spinlock_init(&d->lock);
	return d;
}

static void
free_priv(struct dpdk_priv *d)
{
	for (uint32_t i = 0; i < sa_cap(d); i++)
		if (sa_at(d, i)->used)
			sa_slot_free(d, sa_at(d, i));
	spd_teardown(d);
	r2dp_nh_free(&d->nh);
	rte_ipsec_sad_destroy(d->sad);
	rte_mempool_free(d->sess_mp);
	dp_tables_free(d);
	rte_mempool_free(d->cop_mp);
	rte_free(d->rcu);
	free(d);
}

static uint32_t
peer_of(uint32_t t)
{
	return htonl(0xc6120000u + t);           /* 198.18.0.0 + t */
}

static int
add_tunnel(uint32_t t)
{
	struct fwd_dp da = { .priv = A }, db = { .priv = B };
	struct r2dp_sa r;
	struct r2dp_sp sp;
	uint32_t p = peer_of(t), s = htonl(0xac100000u + t),
	    dd = htonl(0xac1f0000u + t);
	int e = 0;

	memset(&r, 0, sizeof(r));
	r.proto = R2DP_PROTO_ESP; r.mode = R2DP_MODE_TUNNEL;
	r.enc = R2DP_ENCR_AES_GCM_16; r.spi = htonl(0x10000 + t);
	r.enckeylen = 20; r.wsize = 64;
	r.src.family = r.dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "192.0.2.1", r.src.addr);
	memcpy(r.dst.addr, &p, 4);
	memset(&sp, 0, sizeof(sp));
	sp.slid = t + 1; sp.action = R2DP_ACT_PROTECT;
	sp.ul_proto = R2DP_PROTO_ANY;
	sp.sel_src.family = sp.sel_dst.family = R2DP_AF_INET4;
	memcpy(sp.sel_src.addr, &s, 4); sp.pref_src = 32;
	memcpy(sp.sel_dst.addr, &dd, 4); sp.pref_dst = 32;
	sp.tun_src.family = sp.tun_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "192.0.2.1", sp.tun_src.addr);
	memcpy(sp.tun_dst.addr, &p, 4);

	r.dir = R2DP_DIR_OUT;
	e = e ? e : sa_install(A, &r, key, 20, 0, 0);
	sp.dir = R2DP_DIR_OUT;
	e = e ? e : dpd_sp_add(&da, &sp);
	r.dir = R2DP_DIR_IN;
	e = e ? e : sa_install(B, &r, key, 20, 0, 1);
	sp.dir = R2DP_DIR_IN;
	e = e ? e : dpd_sp_add(&db, &sp);
	return e;
}

/* Remove tunnel t: both SAs and both policies (sa_only: A's SA only). */
static void
del_tunnel(uint32_t t, int sa_only)
{
	struct fwd_dp da = { .priv = A }, db = { .priv = B };
	struct r2dp_sa r;
	struct r2dp_sp sp;
	uint32_t p = peer_of(t);

	memset(&r, 0, sizeof(r));
	r.proto = R2DP_PROTO_ESP; r.spi = htonl(0x10000 + t);
	r.src.family = r.dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "192.0.2.1", r.src.addr);
	memcpy(r.dst.addr, &p, 4);
	memset(&sp, 0, sizeof(sp));
	sp.slid = t + 1;
	sa_install(A, &r, NULL, 0, 1, 0);
	if (sa_only)
		return;
	dpd_sp_del(&da, &sp);
	sa_install(B, &r, NULL, 0, 1, 1);
	dpd_sp_del(&db, &sp);
}

static int
nh_known(uint32_t t)
{
	uint8_t mac[6];
	return r2dp_nh_lookup(&A->nh, peer_of(t), mac);
}

/* one packet of tunnel t, A -> B; 1 if it came out intact */
static int
send_one(uint32_t t)
{
	struct rte_mbuf *m = rte_pktmbuf_alloc(mp), *in[1], *esp[1] = { NULL },
	    *dec[BURST_SZ];
	uint16_t nout = 0, nb = 0, ndec = 0, len = 100;
	uint8_t *f, want[100];
	uint32_t s = htonl(0xac100000u + t), dd = htonl(0xac1f0000u + t);
	int ok;

	if (!m)
		return 0;
	f = (uint8_t *)rte_pktmbuf_append(m, 14 + len);
	memset(f, 0, 14 + len);
	f[12] = 0x08;
	f[14] = 0x45; f[17] = (uint8_t)len; f[22] = 64; f[23] = 17;
	memcpy(f + 26, &s, 4);
	memcpy(f + 30, &dd, 4);
	for (int i = 28; i < len; i++) f[14 + i] = (uint8_t)(i ^ t);
	((struct rte_ipv4_hdr *)(f + 14))->hdr_checksum =
	    rte_ipv4_cksum((struct rte_ipv4_hdr *)(f + 14));
	memcpy(want, f + 14, len);
	in[0] = m;
	esp_outbound(&A->wk[0], in, 1, esp, &nout, &nb);
	if (nb && in[0])
		rte_pktmbuf_free(in[0]);
	if (nout != 1)
		return 0;
	if (!rte_pktmbuf_prepend(esp[0], 14)) { rte_pktmbuf_free(esp[0]); return 0; }
	f = rte_pktmbuf_mtod(esp[0], uint8_t *);
	memset(f, 0, 14); f[12] = 0x08;
	esp_inbound(&B->wk[0], esp, 1, dec, &ndec);
	if (ndec != 1)
		return 0;
	ok = rte_pktmbuf_pkt_len(dec[0]) == len &&
	    !memcmp(rte_pktmbuf_mtod(dec[0], uint8_t *), want, len);
	rte_pktmbuf_free(dec[0]);
	return ok;
}

static int
traffic(void *arg)
{
	unsigned me = rte_lcore_id();
	uint64_t x = 88172645463325252ull;

	(void)arg;
	rte_rcu_qsbr_thread_register(A->rcu, me);
	rte_rcu_qsbr_thread_online(A->rcu, me);
	rte_rcu_qsbr_thread_register(B->rcu, me);
	rte_rcu_qsbr_thread_online(B->rcu, me);
	while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE)) {
		uint32_t n = __atomic_load_n(&ready, __ATOMIC_ACQUIRE);
		uint32_t l = __atomic_load_n(&lo, __ATOMIC_ACQUIRE);
		if (n > l) {
			x ^= x << 13; x ^= x >> 7; x ^= x << 17;
			if (send_one(l + (uint32_t)(x % (n - l))))
				n_ok++;
			else
				n_bad++;
		}
		rte_rcu_qsbr_quiescent(A->rcu, me);
		rte_rcu_qsbr_quiescent(B->rcu, me);
	}
	rte_rcu_qsbr_thread_offline(A->rcu, me);
	rte_rcu_qsbr_thread_unregister(A->rcu, me);
	rte_rcu_qsbr_thread_offline(B->rcu, me);
	rte_rcu_qsbr_thread_unregister(B->rcu, me);
	return 0;
}

int
main(void)
{
	char *ea[] = { "dp_grow", "-l", "0-1", "--no-huge", "--no-pci", "-m",
	    "1024", "--vdev=crypto_openssl0", "--log-level=1", NULL };
	struct rte_cryptodev_config cc;
	struct rte_cryptodev_qp_conf qc;
	uint32_t nt = getenv("DP_GROW_NT") ? (uint32_t)atoi(getenv("DP_GROW_NT")) :
	    10000;
	unsigned lc;
	char msg[160];
	double t0;
	int e = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (rte_eal_init(9, ea) < 0 || rte_lcore_count() < 2 ||
	    (cdev = rte_cryptodev_get_dev_id("crypto_openssl0")) < 0) {
		if (getenv("R2DP_REQUIRE_DPDK")) { puts("DPDK setup FAILED"); return 1; }
		puts("SKIP: EAL/crypto_openssl/lcores"); return 77;
	}
	memset(&cc, 0, sizeof(cc)); cc.socket_id = SOCKET_ID_ANY; cc.nb_queue_pairs = 1;
	memset(&qc, 0, sizeof(qc)); qc.nb_descriptors = 256;
	if (rte_cryptodev_configure(cdev, &cc) < 0 ||
	    rte_cryptodev_queue_pair_setup(cdev, 0, &qc, SOCKET_ID_ANY) < 0 ||
	    rte_cryptodev_start(cdev) < 0) { puts("cryptodev FAILED"); return 1; }
	mp = rte_pktmbuf_pool_create("dp_grow_mb", 1024, 0, 0,
	    RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	A = mk_priv("A"); B = mk_priv("B");
	if (!mp || !A || !B) { puts("setup FAILED"); return 1; }

	lc = rte_get_next_lcore(-1, 1, 0);
	rte_eal_remote_launch(traffic, NULL, lc);
	t0 = now_s();
	for (uint32_t t = 0; t < nt && !e; t++) {
		e = add_tunnel(t);
		if (!e)
			__atomic_store_n(&ready, t + 1, __ATOMIC_RELEASE);
	}
	snprintf(msg, sizeof(msg), "%u tunnels installed from empty tables in "
	    "%.1f s (A: sa %u/%u sp %u/%u; B: sad %u/%u, %u session pools)",
	    ready, now_s() - t0, A->sa_n, A->sa_cap, A->sp_n, A->sp_cap,
	    B->sad_n, B->sad_cap, 1 + B->n_sess_more);
	CHECK(!e && ready == nt, msg);
	/* let traffic run over the final tables */
	t0 = now_s();
	while (now_s() - t0 < 0.5)
		rte_pause();
	snprintf(msg, sizeof(msg), "traffic during growth: %llu packets intact, "
	    "%llu lost", (unsigned long long)n_ok, (unsigned long long)n_bad);
	CHECK(n_ok > 0 && n_bad == 0, msg);
	CHECK(A->n_grow_fail == 0 && B->n_grow_fail == 0 && A->n_spd_fail == 0,
	    "no growth failures");

	/* allocation failure: fill A's free SA slots, then growth fails */
	{
		uint32_t before = ready, refused = 0;
		uint64_t ok0 = n_ok, bad0 = n_bad;
		A->inject_grow_fail = B->inject_grow_fail = ~0u;
		for (uint32_t t = ready; t < ready + 2 * DP_CHUNK; t++) {
			int r = add_tunnel(t);
			if (r == -ENOMEM) { refused++; break; }
			if (r) break;
			__atomic_store_n(&ready, t + 1, __ATOMIC_RELEASE);
		}
		snprintf(msg, sizeof(msg), "growth failing: %u more tunnels fit the "
		    "free slots, then an install is refused (-ENOMEM)",
		    ready - before);
		CHECK(refused == 1 && A->n_grow_fail + B->n_grow_fail > 0, msg);
		t0 = now_s();
		while (now_s() - t0 < 0.3)
			rte_pause();
		snprintf(msg, sizeof(msg), "existing tunnels keep forwarding while "
		    "growth fails (%llu more intact, %llu lost)",
		    (unsigned long long)(n_ok - ok0),
		    (unsigned long long)(n_bad - bad0));
		CHECK(n_ok > ok0 && n_bad == bad0, msg);
		A->inject_grow_fail = B->inject_grow_fail = 0;
	}
	/* the half-installed tunnel (A side done, B refused, or A refused):
	 * re-adding is an upsert and completes it */
	{
		uint32_t t = ready;
		int r = add_tunnel(t);
		if (r == -EEXIST || r == 0) r = 0;
		CHECK(r == 0 || r == -EEXIST, "install succeeds again once memory is back");
	}
	/* Next hops follow their peers' last reference.  Learn a MAC for
	 * every peer (the table grows from 8), then, with traffic running on
	 * the rest: delete tunnels [0, 1000) entirely and only the SA of
	 * tunnel 1000 (its OUT policy still names the peer). */
	{
		static const uint8_t mac[6] = { 2, 0, 0, 0, 0, 1 };
		uint32_t n = ready, gone = 0, kept = 0, del = n > 2000 ? 1000 : n / 2;
		uint64_t ok0, bad0, unref0 = A->n_nh_unref;

		for (uint32_t t = 0; t < n; t++)
			while (r2dp_nh_learn(&A->nh, peer_of(t), mac) == 4 ||
			    A->nh.npend)
				r2dp_nh_maint(&A->nh);
		for (int i = 0; i < 4; i++)
			r2dp_nh_maint(&A->nh);
		snprintf(msg, sizeof(msg), "next hops learned for all %u peers "
		    "(table grown to %u)", n, A->nh.cap);
		CHECK(A->nh.n == n, msg);
		__atomic_store_n(&lo, del + 1, __ATOMIC_RELEASE);
		t0 = now_s();
		while (now_s() - t0 < 0.05)
			rte_pause();
		ok0 = n_ok; bad0 = n_bad;
		for (uint32_t t = 0; t < del; t++)
			del_tunnel(t, 0);
		del_tunnel(del, 1);
		for (uint32_t t = 0; t < del; t++)
			gone += !nh_known(t);
		for (uint32_t t = del; t < n; t++)
			kept += nh_known(t);
		snprintf(msg, sizeof(msg), "deleting %u tunnels removed exactly "
		    "their %u next hops (unref_del %llu)", del, gone,
		    (unsigned long long)(A->n_nh_unref - unref0));
		CHECK(gone == del && A->n_nh_unref - unref0 == del, msg);
		snprintf(msg, sizeof(msg), "peers still referenced keep their "
		    "next hop (%u/%u, incl. one with only a policy left)", kept,
		    n - del);
		CHECK(kept == n - del, msg);
		snprintf(msg, sizeof(msg), "live tunnels forwarded throughout the "
		    "deletes (%llu intact, %llu lost)",
		    (unsigned long long)(n_ok - ok0),
		    (unsigned long long)(n_bad - bad0));
		CHECK(n_ok > ok0 && n_bad == bad0, msg);
		{
			struct fwd_dp da = { .priv = A };
			struct r2dp_sp sp;
			memset(&sp, 0, sizeof(sp));
			sp.slid = del + 1;
			dpd_sp_del(&da, &sp);
		}
		CHECK(!nh_known(del), "last reference (the policy) gone -> next hop gone");
	}
	__atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
	rte_eal_mp_wait_lcore();
	free_priv(A);
	free_priv(B);
	rte_mempool_free(mp);
	rte_cryptodev_stop(cdev);
	rte_cryptodev_close(cdev);
	rte_eal_cleanup();
	if (fails) { printf("dp_grow: %d failures\n", fails); return 1; }
	puts("dp_grow: OK");
	return 0;
}

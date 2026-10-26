/*
 * dp_sa: DPDK data-plane SA table tests, run under ASan/UBSan against the
 * production fwd/dp_dpdk.c (included directly so its static functions are
 * reachable).  crypto_openssl vdev, no hugepages, no NIC.
 *
 *  1. C1 regression: a FRESH inbound sa_install used to write
 *     sa_tab[-1].inbound/.dip (idx == -1), corrupting the dpdk_priv fields
 *     just before sa_tab (rcu / rcu_tid / lock).  We fill those with
 *     canaries and require them untouched after fresh and upsert installs,
 *     and that the SAD resolves the new session.
 *  2. sa_by_policy picks the NEWEST outbound SA for a tunnel during a rekey
 *     overlap, regardless of table slot order.
 *
 * SKIP (77) without EAL/crypto_openssl unless R2DP_REQUIRE_DPDK is set.
 */
#include "../fwd/dp_dpdk.c"

static int fails;
#define CHECK(c, m) do { if (c) printf("ok   %s\n", m); \
	else { printf("FAIL %s\n", m); fails++; } } while (0)

static uint8_t key[20] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 0xa,0xb,0xc,0xd };

static struct dpdk_priv *
mk_priv(void)
{
	struct dpdk_priv *d = aligned_alloc(RTE_CACHE_LINE_SIZE, sizeof(*d));
	struct rte_cryptodev_config cc;
	struct rte_cryptodev_qp_conf qc;
	struct rte_ipsec_sad_conf sc;
	int id;

	if (!d)
		return NULL;
	memset(d, 0, sizeof(*d));
	if ((id = rte_cryptodev_get_dev_id("crypto_openssl0")) < 0)
		return NULL;
	d->cdev_id = (uint8_t)id;
	memset(&cc, 0, sizeof(cc)); cc.socket_id = SOCKET_ID_ANY; cc.nb_queue_pairs = 1;
	memset(&qc, 0, sizeof(qc)); qc.nb_descriptors = 256;
	if (rte_cryptodev_configure(d->cdev_id, &cc) < 0 ||
	    rte_cryptodev_queue_pair_setup(d->cdev_id, 0, &qc, SOCKET_ID_ANY) < 0 ||
	    rte_cryptodev_start(d->cdev_id) < 0)
		return NULL;
	d->have_cdev = 1;
	d->sess_mp = rte_cryptodev_sym_session_pool_create("t_sess", 64,
	    rte_cryptodev_sym_get_private_session_size(d->cdev_id), 0, 0,
	    SOCKET_ID_ANY);
	memset(&sc, 0, sizeof(sc));
	sc.socket_id = SOCKET_ID_ANY;
	sc.max_sa[RTE_IPSEC_SAD_SPI_DIP] = 64;
	sc.flags = RTE_IPSEC_SAD_FLAG_RW_CONCURRENCY;
	d->sad = rte_ipsec_sad_create("t_sad", &sc);
	if (!d->sess_mp || !d->sad)
		return NULL;
	rte_spinlock_init(&d->lock);
	return d;
}

static void
mk_sa(struct r2dp_sa *r, uint32_t spi, const char *src, const char *dst)
{
	memset(r, 0, sizeof(*r));
	r->proto = R2DP_PROTO_ESP; r->mode = R2DP_MODE_TUNNEL;
	r->enc = R2DP_ENCR_AES_GCM_16; r->integ = R2DP_INTEG_NONE;
	r->spi = htonl(spi); r->enckeylen = 20;
	r->src.family = r->dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, src, r->src.addr);
	inet_pton(AF_INET, dst, r->dst.addr);
}

/* --- M4: concurrent policy replace vs. a QSBR-registered reader --- */
static volatile int rd_stop;
static unsigned long rd_iters, rd_torn;

static void
fill_sp(struct r2dp_sp *sp, uint32_t slid, uint8_t k)
{
	memset(sp, 0, sizeof(*sp));
	sp->slid = slid;
	sp->dir = R2DP_DIR_OUT; sp->action = R2DP_ACT_PROTECT;
	memset(sp->tag, k, sizeof(sp->tag));
	sp->sel_src.family = sp->sel_dst.family = R2DP_AF_INET4;
	memset(sp->sel_src.addr, k, 4);
	memset(sp->sel_dst.addr, k, 4);
	sp->pref_src = sp->pref_dst = k % 33;
}

static int
reader(void *arg)
{
	struct dpdk_priv *d = arg;

	rte_rcu_qsbr_thread_register(d->rcu, d->worker_lcore);
	rte_rcu_qsbr_thread_online(d->rcu, d->worker_lcore);
	while (!rd_stop) {
		for (int i = 0; i < 8; i++) {
			const struct r2dp_sp *sp = sp_load(&d->sp_tab[i]);
			uint8_t k;
			if (!sp)
				continue;
			k = sp->tag[0];
			/* every byte of a published policy must be consistent */
			for (unsigned j = 0; j < sizeof(sp->tag); j++)
				if ((uint8_t)sp->tag[j] != k) rd_torn++;
			if (sp->sel_src.addr[3] != k || sp->sel_dst.addr[0] != k ||
			    sp->pref_src != k % 33)
				rd_torn++;
		}
		rd_iters++;
		rte_rcu_qsbr_quiescent(d->rcu, d->worker_lcore);
	}
	rte_rcu_qsbr_thread_offline(d->rcu, d->worker_lcore);
	rte_rcu_qsbr_thread_unregister(d->rcu, d->worker_lcore);
	return 0;
}

static void
t_sp_concurrency(struct dpdk_priv *d)
{
	struct fwd_dp dp = { .priv = d };
	struct r2dp_sp sp;
	unsigned lc = rte_get_next_lcore(-1, 1, 0);   /* first worker lcore */
	size_t rsz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);

	if (lc >= RTE_MAX_LCORE) { CHECK(0, "need a worker lcore (-l 0-1)"); return; }
	d->worker_lcore = lc;      /* same tid convention as dpd_start */
	d->rcu = rte_zmalloc("t_rcu", rsz, RTE_CACHE_LINE_SIZE);
	if (!d->rcu) { CHECK(0, "rcu alloc"); return; }
	rte_rcu_qsbr_init(d->rcu, RTE_MAX_LCORE);
	rd_stop = 0;
	/* run the reader on a real EAL worker lcore, like worker_main */
	rte_eal_remote_launch(reader, d, lc);
	while (!__atomic_load_n(&rd_iters, __ATOMIC_RELAXED))
		;                       /* reader online before churn */
	for (unsigned n = 0; n < 5000; n++) {
		uint32_t slid = 1 + n % 4;
		fill_sp(&sp, slid, (uint8_t)(n & 0xff));
		if (n % 7 == 6)
			dpd_sp_del(&dp, &sp);
		else
			dpd_sp_add(&dp, &sp);
	}
	rd_stop = 1;
	rte_eal_wait_lcore(lc);
	CHECK(rd_iters > 0, "reader ran concurrently with policy churn");
	CHECK(rd_torn == 0, "no torn policy reads under concurrent replace/delete");
	for (int i = 0; i < MAX_SA; i++)
		if (d->sp_tab[i].sp) {
			free(d->sp_tab[i].sp);
			d->sp_tab[i].sp = NULL;
		}
	rte_free(d->rcu);
	d->rcu = NULL;
}

/* --- M5: inbound check is tied to the SA's own policies, default deny --- */
static size_t
ipkt(uint8_t *p, const char *src, const char *dst)
{
	memset(p, 0, 40);
	p[0] = 0x45; p[9] = 1;
	inet_pton(AF_INET, src, p + 12);
	inet_pton(AF_INET, dst, p + 16);
	return 40;
}

static void
add_in_sp(struct dpdk_priv *d, uint32_t slid, const char *peer,
    const char *ssel, const char *dsel)
{
	struct fwd_dp dp = { .priv = d };
	struct r2dp_sp sp;

	memset(&sp, 0, sizeof(sp));
	sp.slid = slid; sp.dir = R2DP_DIR_IN; sp.action = R2DP_ACT_PROTECT;
	sp.ul_proto = R2DP_PROTO_ANY;
	sp.sel_src.family = sp.sel_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, ssel, sp.sel_src.addr); sp.pref_src = 24;
	inet_pton(AF_INET, dsel, sp.sel_dst.addr); sp.pref_dst = 24;
	sp.tun_src.family = sp.tun_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, peer, sp.tun_src.addr);
	inet_pton(AF_INET, "192.0.2.1", sp.tun_dst.addr);
	dpd_sp_add(&dp, &sp);
}

static void
t_inbound_policy(struct dpdk_priv *d)
{
	struct dp_sa a, b;
	uint8_t p[40];

	memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));
	inet_pton(AF_INET, "192.0.2.2", &a.srca);    /* peer A */
	inet_pton(AF_INET, "192.0.2.3", &b.srca);    /* peer B */
	inet_pton(AF_INET, "192.0.2.1", &a.dsta);
	inet_pton(AF_INET, "192.0.2.1", &b.dsta);

	ipkt(p, "10.0.2.5", "10.0.1.5");
	CHECK(!inbound_policy_ok(d, &a, p, 40),
	    "no IN policy for the SA -> drop (default deny)");

	add_in_sp(d, 101, "192.0.2.2", "10.0.2.0", "10.0.1.0");  /* A: 10.0.2/24 */
	add_in_sp(d, 102, "192.0.2.3", "10.0.3.0", "10.0.1.0");  /* B: 10.0.3/24 */

	ipkt(p, "10.0.2.5", "10.0.1.5");
	CHECK(inbound_policy_ok(d, &a, p, 40), "A's traffic under A's SA accepted");
	CHECK(!inbound_policy_ok(d, &b, p, 40),
	    "A's selectors under B's SA rejected (no cross-tunnel injection)");
	ipkt(p, "10.0.3.5", "10.0.1.5");
	CHECK(inbound_policy_ok(d, &b, p, 40),
	    "B's traffic under B's SA accepted (not judged by A's policy)");
	CHECK(!inbound_policy_ok(d, &a, p, 40), "B's selectors under A's SA rejected");

	for (int i = 0; i < MAX_SA; i++)
		if (d->sp_tab[i].sp) { free(d->sp_tab[i].sp); d->sp_tab[i].sp = NULL; }
}

int
main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char *ea[] = { "dp_sa", "--no-huge", "--no-pci", "-m", "256",
	    "--vdev=crypto_openssl0", "--log-level=1", "-l", "0-1", NULL };
	struct dpdk_priv *d;
	struct r2dp_sa r;
	struct r2dp_sp sp;
	struct rte_rcu_qsbr *canary_rcu = (struct rte_rcu_qsbr *)(uintptr_t)0;
	const unsigned canary_tid = 0xC1C1C1C1u;
	union rte_ipsec_sad_key k;
	const union rte_ipsec_sad_key *kp[1] = { &k };
	void *val[1];

	if (rte_eal_init(9, ea) < 0 || (d = mk_priv()) == NULL) {
		if (getenv("R2DP_REQUIRE_DPDK")) { puts("DPDK setup FAILED"); return 1; }
		puts("SKIP: EAL/crypto_openssl"); return 77;
	}

	/* --- 1. C1: fresh inbound install must not write before sa_tab --- */
	d->rcu = canary_rcu;            /* NULL: no worker, no synchronize */
	d->rcu_tid = canary_tid;
	{
		rte_spinlock_t lk = d->lock;
		uint8_t have = (uint8_t)d->have_cdev;
		mk_sa(&r, 0x1001, "192.0.2.2", "192.0.2.1");
		CHECK(sa_install(d, &r, key, 20, 0, 1) == 0, "fresh inbound sa_install");
		CHECK(d->rcu_tid == canary_tid && d->rcu == canary_rcu &&
		    memcmp(&lk, &d->lock, sizeof(lk)) == 0 &&
		    d->have_cdev == have,
		    "fields before sa_tab untouched (no sa_tab[-1] write)");
		memset(&k, 0, sizeof(k));
		k.v4.spi = 0x1001; memcpy(&k.v4.dip, r.dst.addr, 4);
		CHECK(rte_ipsec_sad_lookup(d->sad, kp, val, 1) == 1 && val[0] != NULL,
		    "SAD resolves the fresh inbound SA");
		CHECK(val[0] && ((struct dp_sa *)((char *)val[0] -
		    offsetof(struct dp_sa, sess)))->inbound == 1, "SA marked inbound");

		/* upsert (same SPI/DIP): the old slot is retired, new one live */
		CHECK(sa_install(d, &r, key, 20, 0, 1) == 0, "inbound upsert");
		CHECK(d->rcu_tid == canary_tid, "upsert leaves canary intact");
		CHECK(rte_ipsec_sad_lookup(d->sad, kp, val, 1) == 1 && val[0] != NULL,
		    "SAD resolves the upserted SA");
		CHECK(sa_install(d, &r, NULL, 0, 1, 1) == 0, "inbound delete");
		CHECK(rte_ipsec_sad_lookup(d->sad, kp, val, 1) == 0,
		    "SAD empty after delete");
	}

	/* --- 2. sa_by_policy prefers the newest outbound SA --- */
	{
		struct dp_sa *pick;
		int old_slot = -1, new_slot = -1;

		mk_sa(&r, 0x2001, "192.0.2.1", "192.0.2.2");      /* old SA */
		CHECK(sa_install(d, &r, key, 20, 0, 0) == 0, "outbound SA #1");
		mk_sa(&r, 0x2002, "192.0.2.1", "192.0.2.2");      /* rekeyed SA */
		CHECK(sa_install(d, &r, key, 20, 0, 0) == 0, "outbound SA #2");
		for (int i = 0; i < MAX_SA; i++) {
			if (!d->sa_tab[i].used) continue;
			if (d->sa_tab[i].spi == 0x2001) old_slot = i;
			if (d->sa_tab[i].spi == 0x2002) new_slot = i;
		}
		/* force the OLD SA into a later slot than the new one, so a
		 * "last matching slot" policy would pick the wrong SA */
		if (old_slot >= 0 && new_slot >= 0 && old_slot < new_slot) {
			struct dp_sa t = d->sa_tab[old_slot];
			d->sa_tab[old_slot] = d->sa_tab[new_slot];
			d->sa_tab[new_slot] = t;
		}
		memset(&sp, 0, sizeof(sp));
		sp.dir = R2DP_DIR_OUT; sp.action = R2DP_ACT_PROTECT;
		sp.reqid = 0x5150;     /* derived reqid that the SAs don't carry */
		sp.tun_src.family = sp.tun_dst.family = R2DP_AF_INET4;
		inet_pton(AF_INET, "192.0.2.1", sp.tun_src.addr);
		inet_pton(AF_INET, "192.0.2.2", sp.tun_dst.addr);
		pick = sa_by_policy(d, &sp);
		CHECK(pick && pick->spi == 0x2002, "egress picks newest SA (endpoint match)");
		sp.reqid = 0;
		pick = sa_by_policy(d, &sp);
		CHECK(pick && pick->spi == 0x2002, "egress picks newest SA (reqid 0)");
	}

	t_sp_concurrency(d);
	t_inbound_policy(d);

	/* teardown: free every session (no leaks under LSan) */
	for (int i = 0; i < MAX_SA; i++)
		if (d->sa_tab[i].used)
			sa_slot_free(d, &d->sa_tab[i]);
	rte_ipsec_sad_destroy(d->sad);
	rte_mempool_free(d->sess_mp);
	rte_cryptodev_stop(d->cdev_id);
	rte_cryptodev_close(d->cdev_id);
	free(d);
	rte_eal_cleanup();

	if (fails) { printf("dp_sa: %d failures\n", fails); return 1; }
	puts("dp_sa: OK");
	return 0;
}

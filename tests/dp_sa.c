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
 *  3. Inbound SAD (ATOMICS A1, SADB S1-S3): a reader resolving a live SA
 *     never misses it while other inbound SAs churn and the SAD grows by
 *     swap from a tiny size; no install fails for want of SAD room; an
 *     update that flips direction is refused with the old SA untouched.
 *
 * SKIP (77) without EAL/crypto_openssl unless R2DP_REQUIRE_DPDK is set.
 */
#include "lc_sync.h"
#include "dpdk_int.h"

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
	int id;

	if (!d)
		return NULL;
	memset(d, 0, sizeof(*d));
	d->nb_wk = 1;
	dp_wk_init(d, 0);
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
	d->sad = dp_sad_create("t_sad", 64);
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

	rte_rcu_qsbr_thread_register(d->rcu, d->wk[0].lcore);
	rte_rcu_qsbr_thread_online(d->rcu, d->wk[0].lcore);
	while (!__atomic_load_n(&rd_stop, __ATOMIC_ACQUIRE)) {
		for (int i = 0; i < 8 && i < (int)sp_cap(d); i++) {
			const struct r2dp_sp *sp = sp_load(sp_at(d, (uint32_t)i));
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
		/* the published snapshot (what the egress path reads) */
		{
			const struct dp_spd *ss = __atomic_load_n(&d->spd, __ATOMIC_ACQUIRE);
			for (uint32_t i = 0; ss && i < ss->nout; i++) {
				const struct r2dp_sp *sp = ss->out[i].sp;
				uint8_t k = sp->tag[0];
				for (unsigned j = 0; j < sizeof(sp->tag); j++)
					if ((uint8_t)sp->tag[j] != k) rd_torn++;
				if (sp->sel_src.addr[3] != k || (i && ss->out[i - 1].score < ss->out[i].score))
					rd_torn++;
			}
		}
		__atomic_fetch_add(&rd_iters, 1, __ATOMIC_RELAXED);
		rte_rcu_qsbr_quiescent(d->rcu, d->wk[0].lcore);
	}
	rte_rcu_qsbr_thread_offline(d->rcu, d->wk[0].lcore);
	rte_rcu_qsbr_thread_unregister(d->rcu, d->wk[0].lcore);
	return 0;
}

/* --- SAD: lock-free lookups stay correct across churn and growth --- */
static unsigned long sad_rd_iters, sad_rd_miss;
static union rte_ipsec_sad_key sad_rd_key;

static int
sad_reader(void *arg)
{
	struct dpdk_priv *d = arg;
	const union rte_ipsec_sad_key *kp[1] = { &sad_rd_key };

	rte_rcu_qsbr_thread_register(d->rcu, d->wk[0].lcore);
	rte_rcu_qsbr_thread_online(d->rcu, d->wk[0].lcore);
	while (!__atomic_load_n(&rd_stop, __ATOMIC_ACQUIRE)) {
		void *v[1];
		const struct dp_sa *ds;

		if (dp_sad_lookup(sad_load(d), kp, v, 1) != 1 || !v[0])
			sad_rd_miss++;
		else {
			ds = sa_of_sess(d, v[0]);
			/* a retiring slot is still intact until the grace
			 * period ends: what matters is it is never freed or
			 * reused while this reader can hold it */
			if (!ds || ds->spi != sad_rd_key.v4.spi)
				sad_rd_miss++;
		}
		__atomic_fetch_add(&sad_rd_iters, 1, __ATOMIC_RELAXED);
		rte_rcu_qsbr_quiescent(d->rcu, d->wk[0].lcore);
	}
	rte_rcu_qsbr_thread_offline(d->rcu, d->wk[0].lcore);
	rte_rcu_qsbr_thread_unregister(d->rcu, d->wk[0].lcore);
	return 0;
}

static void
t_sad(struct dpdk_priv *d)
{
	enum { NCH = 600 };
	struct r2dp_sa r;
	unsigned lc = rte_get_next_lcore(-1, 1, 0);
	size_t rsz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	struct rte_hash *small;
	uint32_t n0 = d->sad_n, cap0 = d->sad_cap, rej = 0;
	struct rte_hash *orig = d->sad;
	char ip[32];

	if (lc >= RTE_MAX_LCORE) { CHECK(0, "need a worker lcore (-l 0-1)"); return; }
	/* start from a tiny growable SAD so the churn forces several swaps */
	small = dp_sad_create("t_sad_small", 8);
	if (!small) { CHECK(0, "small SAD"); return; }
	d->sad = small;
	d->sad_cap = 8;
	d->sad_n = 0;
	d->wk[0].lcore = lc;
	d->rcu = rte_zmalloc("t_rcu2", rsz, RTE_CACHE_LINE_SIZE);
	if (!d->rcu) { CHECK(0, "rcu alloc"); return; }
	rte_rcu_qsbr_init(d->rcu, RTE_MAX_LCORE);

	mk_sa(&r, 0x7000, "192.0.2.2", "192.0.2.1");          /* the live SA */
	CHECK(sa_install(d, &r, key, 20, 0, 1) == 0, "sad: live inbound SA");
	memset(&sad_rd_key, 0, sizeof(sad_rd_key));
	sad_rd_key.v4.spi = 0x7000;
	memcpy(&sad_rd_key.v4.dip, r.dst.addr, 4);
	rd_stop = 0;
	lc_launch(sad_reader, d, lc);
	while (!__atomic_load_n(&sad_rd_iters, __ATOMIC_RELAXED))
		;
	for (unsigned n = 0; n < NCH; n++) {           /* churn + growth */
		snprintf(ip, sizeof(ip), "198.51.%u.%u", 100 + n / 250, 1 + n % 250);
		mk_sa(&r, 0x8000 + n, ip, "192.0.2.1");
		if (sa_install(d, &r, key, 20, 0, 1) != 0)
			rej++;
		if (n % 3 == 2) {                    /* delete an older one */
			snprintf(ip, sizeof(ip), "198.51.%u.%u", 100 + (n - 2) / 250,
			    1 + (n - 2) % 250);
			mk_sa(&r, 0x8000 + n - 2, ip, "192.0.2.1");
			(void)sa_install(d, &r, NULL, 0, 1, 1);
		}
		mk_sa(&r, 0x7000, "192.0.2.2", "192.0.2.1");   /* rekey-style upsert */
		if (n % 50 == 0 && sa_install(d, &r, key, 20, 0, 1) != 0)
			rej++;
	}
	__atomic_store_n(&rd_stop, 1, __ATOMIC_RELEASE);
	lc_wait_all();
	CHECK(sad_rd_iters > 0 && sad_rd_miss == 0,
	    "sad: live SA resolved on every lookup through churn, upserts and growth");
	CHECK(rej == 0, "sad: no install refused for want of SAD room");
	CHECK(d->sad_cap >= 512 && d->sad_n == 1 + NCH - NCH / 3,
	    "sad: grew by swap; sad_n counts exactly the live inbound SAs");

	/* S3: same (SPI, DIP, proto) re-sent as outbound is refused */
	mk_sa(&r, 0x7000, "192.0.2.2", "192.0.2.1");
	{
		uint32_t n1 = d->sad_n;
		const union rte_ipsec_sad_key *kp[1] = { &sad_rd_key };
		void *v[1];
		CHECK(sa_install(d, &r, key, 20, 0, 0) == -EINVAL,
		    "sad: direction flip on update refused (-EINVAL)");
		CHECK(dp_sad_lookup(d->sad, kp, v, 1) == 1 && v[0] &&
		    sa_live(sa_of_sess(d, v[0])) && d->sad_n == n1,
		    "sad: inbound SA still resolves after the refused flip, sad_n unchanged");
	}

	/* clean up: every inbound SA this test added */
	mk_sa(&r, 0x7000, "192.0.2.2", "192.0.2.1");
	(void)sa_install(d, &r, NULL, 0, 1, 1);
	for (unsigned n = 0; n < NCH; n++) {
		snprintf(ip, sizeof(ip), "198.51.%u.%u", 100 + n / 250, 1 + n % 250);
		mk_sa(&r, 0x8000 + n, ip, "192.0.2.1");
		(void)sa_install(d, &r, NULL, 0, 1, 1);
	}
	CHECK(d->sad_n == 0, "sad: empty after cleanup");
	rte_free(d->rcu);
	d->rcu = NULL;
	dp_sad_destroy(d->sad);
	d->sad = orig;
	d->sad_cap = cap0;
	d->sad_n = n0;
}

static void
t_sp_concurrency(struct dpdk_priv *d)
{
	struct fwd_dp dp = { .priv = d };
	struct r2dp_sp sp;
	unsigned lc = rte_get_next_lcore(-1, 1, 0);   /* first worker lcore */
	size_t rsz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);

	if (lc >= RTE_MAX_LCORE) { CHECK(0, "need a worker lcore (-l 0-1)"); return; }
	d->wk[0].lcore = lc;      /* same tid convention as dpd_start */
	d->rcu = rte_zmalloc("t_rcu", rsz, RTE_CACHE_LINE_SIZE);
	if (!d->rcu) { CHECK(0, "rcu alloc"); return; }
	rte_rcu_qsbr_init(d->rcu, RTE_MAX_LCORE);
	rd_stop = 0;
	/* run the reader on a real EAL worker lcore, like worker_main */
	lc_launch(reader, d, lc);
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
	__atomic_store_n(&rd_stop, 1, __ATOMIC_RELEASE);
	lc_wait_all();
	CHECK(rd_iters > 0, "reader ran concurrently with policy churn");
	CHECK(rd_torn == 0, "no torn policy reads under concurrent replace/delete");
	spd_teardown(d);
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

	spd_teardown(d);
}

/* Our anti-replay window (librte_ipsec's drops bits 32..63 of each
 * bucket): duplicates in every bit position, window edges, windows > 64,
 * and ESN reconstruction across a 2^32 wrap. */
/* The bit-at-a-time window advance replay_accept used before the
 * word-wise clear (REPLAY R2): the reference for the differential test. */
static int
ref_accept(struct dp_sa *ds, uint32_t lo)
{
	uint64_t t = ds->rp_top, sqn = lo;
	uint32_t w = ds->rp_w, tl = (uint32_t)t;

	if (!w)
		return 1;
	if (ds->rp_esn) {
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
	if (sqn > t) {
		uint64_t d = sqn - t;
		if (d >= RP_BITS)
			memset(ds->rp_map, 0, sizeof(ds->rp_map));
		else
			for (uint64_t s = t + 1; s <= sqn; s++)
				ds->rp_map[(s % RP_BITS) / 64] &= ~(1ull << (s % 64));
		ds->rp_top = sqn;
	} else if (t - sqn >= w) {
		return 0;
	} else if (ds->rp_map[(sqn % RP_BITS) / 64] & (1ull << (sqn % 64))) {
		return 0;
	}
	ds->rp_map[(sqn % RP_BITS) / 64] |= 1ull << (sqn % 64);
	return 1;
}

static void
t_replay_diff(void)
{
	static const uint32_t jump[] = { 1, 2, 63, 64, 65, 127, 128, 129, 500,
	    1000, 1023, 1024, 1025, 4096 };
	static const uint32_t win[] = { 32, 64, 200, RP_BITS };
	static struct dp_sa a, b;
	unsigned long diff = 0, n = 0;
	uint64_t rnd = 0x9e3779b97f4a7c15ull;

	for (unsigned wi = 0; wi < RTE_DIM(win); wi++)
		for (int esn = 0; esn < 2; esn++) {
			uint32_t q = esn ? 0xffffff00u : 1;
			memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));
			a.rp_w = b.rp_w = win[wi];
			a.rp_esn = b.rp_esn = (uint8_t)esn;
			for (unsigned i = 0; i < 4000; i++, n++) {
				rnd ^= rnd << 13; rnd ^= rnd >> 7; rnd ^= rnd << 17;
				switch (rnd % 4) {
				case 0: case 1:          /* forward jump */
					q += jump[(rnd >> 8) % RTE_DIM(jump)];
					break;
				case 2:                  /* late, maybe replayed */
					q -= (uint32_t)((rnd >> 8) % (win[wi] + 70));
					break;
				default:                 /* exact duplicate */
					break;
				}
				if (replay_accept(&a, q) != ref_accept(&b, q) ||
				    a.rp_top != b.rp_top ||
				    memcmp(a.rp_map, b.rp_map, sizeof(a.rp_map)))
					diff++;
			}
		}
	CHECK(n && !diff, "replay: word-wise window advance matches the bit loop "
	    "(jumps 1..4096, windows 32..1024, ESN wrap)");
}

static void
t_replay_window(void)
{
	static struct dp_sa s;
	int bad = 0;

	memset(&s, 0, sizeof(s)); s.rp_w = 64;
	for (uint32_t q = 1; q <= 300; q++)
		bad += !replay_accept(&s, q);
	for (uint32_t q = 237; q <= 300; q++)       /* every bit position */
		bad += replay_accept(&s, q);
	CHECK(!bad, "replay: each of the last 64 seqs accepted once, then refused");
	CHECK(!replay_accept(&s, 236), "replay: distance 64 is outside a 64-window");
	CHECK(!replay_accept(&s, 0), "replay: seq 0 refused");
	CHECK(replay_accept(&s, 1000) && replay_accept(&s, 937) && !replay_accept(&s, 936),
	    "replay: jump ahead, then the oldest slot in, one past it out");

	memset(&s, 0, sizeof(s)); s.rp_w = 200;
	CHECK(replay_accept(&s, 500) && replay_accept(&s, 301) && !replay_accept(&s, 300) &&
	    !replay_accept(&s, 301), "replay: 200-packet window (> 64) honoured");

	memset(&s, 0, sizeof(s)); s.rp_w = RP_BITS;   /* widest window: 1024 */
	bad = 0;
	for (uint32_t q = 1; q <= 3000; q++)
		bad += !replay_accept(&s, q);
	for (uint32_t q = 3000 - RP_BITS + 1; q <= 3000; q++)
		bad += replay_accept(&s, q);
	CHECK(!bad && !replay_accept(&s, 3000 - RP_BITS),
	    "replay: 1024-packet window, every slot refused once, edge outside");
	CHECK(replay_accept(&s, 3000 + RP_BITS - 1) && !replay_accept(&s, 3000) &&
	    !replay_accept(&s, 2999) && replay_accept(&s, 3500),
	    "replay: slide by window-1 keeps the oldest seen, drops what fell out");

	memset(&s, 0, sizeof(s)); s.rp_w = 0;     /* wsize 0: PF_KEY "off" */
	CHECK(replay_accept(&s, 7) && replay_accept(&s, 7) && replay_accept(&s, 1),
	    "replay: window 0 disables anti-replay (duplicates and old seqs pass)");

	memset(&s, 0, sizeof(s)); s.rp_w = 64; s.rp_esn = 1;
	s.rp_top = 0xfffffff0ull;
	CHECK(replay_accept(&s, 5) && s.rp_top == 0x100000005ull,
	    "replay/ESN: low seq after the top wraps into the next epoch");
	CHECK(replay_accept(&s, 0xfffffff8u) && !replay_accept(&s, 0xfffffff8u),
	    "replay/ESN: late packet from the previous epoch once, not twice");
}

/* sa_install carries the requested window into both our window and
 * librte_ipsec's: 0 (off) installs with and without ESN. */
static struct dp_sa *
sa_by_spi(struct dpdk_priv *d, uint32_t spi)
{
	for (int i = 0; i < (int)sa_cap(d); i++)
		if ((*sa_at(d, (uint32_t)(i))).used && (*sa_at(d, (uint32_t)(i))).spi == spi)
			return &(*sa_at(d, (uint32_t)(i)));
	return NULL;
}

static void
t_wsize_install(struct dpdk_priv *d)
{
	struct r2dp_sa r;
	struct dp_sa *s;

	mk_sa(&r, 0x5001, "192.0.2.2", "192.0.2.1");
	r.wsize = 0;
	CHECK(sa_install(d, &r, key, 20, 0, 1) == 0 && (s = sa_by_spi(d, 0x5001)) &&
	    s->rp_w == 0, "wsize 0: inbound SA installs with anti-replay off");
	sa_install(d, &r, NULL, 0, 1, 1);
	r.saflags = R2DP_SAF_ESN;
	CHECK(sa_install(d, &r, key, 20, 0, 1) == 0 && (s = sa_by_spi(d, 0x5001)) &&
	    s->rp_w == 0 && s->rp_esn, "wsize 0 + ESN: installs (rte_ipsec keeps 64 for ESN)");
	sa_install(d, &r, NULL, 0, 1, 1);
	r.wsize = 255; r.replay_win = 1024;
	CHECK(sa_install(d, &r, key, 20, 0, 1) == 0 && (s = sa_by_spi(d, 0x5001)) &&
	    s->rp_w == 1024, "replay_win 1024 (ESN) overrides the u8 wsize");
	sa_install(d, &r, NULL, 0, 1, 1);
	r.replay_win = 0;
	r.saflags = 0; r.wsize = 200;
	CHECK(sa_install(d, &r, key, 20, 0, 1) == 0 && (s = sa_by_spi(d, 0x5001)) &&
	    s->rp_w == 200, "wsize 200 carried to the SA");
	sa_install(d, &r, NULL, 0, 1, 1);
}

/* Indexed inbound check (installed SAs -> snapshot per-SA policy list) and
 * the hashed tunnel-peer set; plus the fallback scan when the snapshot was
 * not rebuilt for an SA (generation mismatch). */
static void
t_inbound_indexed(struct dpdk_priv *d)
{
	struct r2dp_sa r;
	struct dp_sa *a = NULL, *b = NULL;
	const struct dp_spd *s;
	uint8_t p[40];
	uint32_t ip;

	add_in_sp(d, 201, "192.0.2.2", "10.0.2.0", "10.0.1.0");
	add_in_sp(d, 202, "192.0.2.3", "10.0.3.0", "10.0.1.0");
	mk_sa(&r, 0x4001, "192.0.2.2", "192.0.2.1");
	CHECK(sa_install(d, &r, key, 20, 0, 1) == 0, "idx: inbound SA A");
	mk_sa(&r, 0x4002, "192.0.2.3", "192.0.2.1");
	CHECK(sa_install(d, &r, key, 20, 0, 1) == 0, "idx: inbound SA B");
	for (int i = 0; i < (int)sa_cap(d); i++) {
		if (!(*sa_at(d, (uint32_t)(i))).used) continue;
		if ((*sa_at(d, (uint32_t)(i))).spi == 0x4001) a = &(*sa_at(d, (uint32_t)(i)));
		if ((*sa_at(d, (uint32_t)(i))).spi == 0x4002) b = &(*sa_at(d, (uint32_t)(i)));
	}
	s = d->spd;
	CHECK(a && b && s && s->in_gen[a->idx] == a->gen &&
	    s->in_off[a->idx + 1] - s->in_off[a->idx] == 1,
	    "idx: snapshot holds exactly A's IN policy for SA A");
	ipkt(p, "10.0.2.5", "10.0.1.5");
	CHECK(inbound_policy_ok(d, a, p, 40) && !inbound_policy_ok(d, b, p, 40),
	    "idx: A's traffic only under A's SA");
	ipkt(p, "10.0.3.5", "10.0.1.5");
	CHECK(inbound_policy_ok(d, b, p, 40) && !inbound_policy_ok(d, a, p, 40),
	    "idx: B's traffic only under B's SA");
	a->gen += 1000;                         /* snapshot stale for A */
	ipkt(p, "10.0.2.5", "10.0.1.5");
	CHECK(inbound_policy_ok(d, a, p, 40), "idx: stale snapshot falls back to a scan");
	a->gen -= 1000;

	inet_pton(AF_INET, "192.0.2.2", &ip);
	CHECK(is_tunnel_peer(d, ip), "peer: inbound SA source is a peer");
	inet_pton(AF_INET, "192.0.2.99", &ip);
	CHECK(!is_tunnel_peer(d, ip), "peer: unrelated host is not");
	inet_pton(AF_INET, "0.0.0.0", &ip);
	CHECK(!is_tunnel_peer(d, ip), "peer: 0.0.0.0 is not");
	mk_sa(&r, 0x4001, "192.0.2.2", "192.0.2.1");
	sa_install(d, &r, NULL, 0, 1, 1);
	mk_sa(&r, 0x4002, "192.0.2.3", "192.0.2.1");
	sa_install(d, &r, NULL, 0, 1, 1);
	inet_pton(AF_INET, "192.0.2.3", &ip);
	CHECK(is_tunnel_peer(d, ip), "peer: IN PROTECT policy tun_src stays a peer");
	spd_teardown(d);
	inet_pton(AF_INET, "192.0.2.3", &ip);
	CHECK(!is_tunnel_peer(d, ip), "peer: gone after policies removed");
}

/* Control-time policy->SA binding: the egress path reads the binding from
 * the published snapshot (no SA scan); rekey rebinds to the newest SA, a
 * delete rebinds to what is left, a stale binding fails closed, and the
 * most specific policy wins independent of table order. */
static void
t_binding(struct dpdk_priv *d)
{
	struct fwd_dp dp = { .priv = d };
	struct r2dp_sp sp;
	struct r2dp_sa r;
	struct dp_sa *ds = NULL;
	const struct r2dp_sp *m;
	uint8_t pkt[40];

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x45; pkt[9] = 17;
	inet_pton(AF_INET, "10.9.0.5", pkt + 12);
	inet_pton(AF_INET, "10.8.0.5", pkt + 16);
	pkt[22] = 0; pkt[23] = 53;

	memset(&sp, 0, sizeof(sp));
	sp.slid = 77; sp.dir = R2DP_DIR_OUT; sp.action = R2DP_ACT_PROTECT;
	sp.ul_proto = R2DP_PROTO_ANY;
	sp.sel_src.family = sp.sel_dst.family = R2DP_AF_INET4;
	sp.tun_src.family = sp.tun_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "10.9.0.0", sp.sel_src.addr); sp.pref_src = 24;
	inet_pton(AF_INET, "10.8.0.0", sp.sel_dst.addr); sp.pref_dst = 24;
	inet_pton(AF_INET, "192.0.2.21", sp.tun_src.addr);
	inet_pton(AF_INET, "192.0.2.22", sp.tun_dst.addr);
	CHECK(dpd_sp_add(&dp, &sp) == 0, "bind: OUT policy installed");
	m = sp_match_out(d, (const struct rte_ipv4_hdr *)pkt, sizeof(pkt), &ds);
	CHECK(m && m->slid == 77 && !ds, "bind: PROTECT without an SA -> no SA (drop)");

	mk_sa(&r, 0x3001, "192.0.2.21", "192.0.2.22");
	CHECK(sa_install(d, &r, key, 20, 0, 0) == 0, "bind: SA #1");
	m = sp_match_out(d, (const struct rte_ipv4_hdr *)pkt, sizeof(pkt), &ds);
	CHECK(ds && ds->spi == 0x3001, "bind: policy bound to SA #1 at install");
	mk_sa(&r, 0x3002, "192.0.2.21", "192.0.2.22");
	CHECK(sa_install(d, &r, key, 20, 0, 0) == 0, "bind: SA #2 (rekey)");
	m = sp_match_out(d, (const struct rte_ipv4_hdr *)pkt, sizeof(pkt), &ds);
	CHECK(ds && ds->spi == 0x3002, "bind: rekey rebinds to the newest SA");
	CHECK(sa_install(d, &r, NULL, 0, 1, 0) == 0, "bind: delete SA #2");
	m = sp_match_out(d, (const struct rte_ipv4_hdr *)pkt, sizeof(pkt), &ds);
	CHECK(ds && ds->spi == 0x3001, "bind: delete rebinds to the remaining SA");
	ds->gen += 1000;                         /* slot reused behind our back */
	m = sp_match_out(d, (const struct rte_ipv4_hdr *)pkt, sizeof(pkt), &ds);
	CHECK(m && !ds, "bind: stale binding (generation mismatch) fails closed");
	for (int i = 0; i < (int)sa_cap(d); i++)
		if ((*sa_at(d, (uint32_t)(i))).used && (*sa_at(d, (uint32_t)(i))).spi == 0x3001)
			(*sa_at(d, (uint32_t)(i))).gen -= 1000;

	/* a more specific DISCARD installed later still wins */
	sp.slid = 78; sp.action = R2DP_ACT_DISCARD;
	inet_pton(AF_INET, "10.9.0.5", sp.sel_src.addr); sp.pref_src = 32;
	CHECK(dpd_sp_add(&dp, &sp) == 0, "bind: specific DISCARD installed");
	m = sp_match_out(d, (const struct rte_ipv4_hdr *)pkt, sizeof(pkt), &ds);
	CHECK(m && m->slid == 78 && m->action == R2DP_ACT_DISCARD,
	    "bind: most specific policy wins regardless of slot order");
	CHECK(dpd_sp_del(&dp, &sp) == 0, "bind: DISCARD removed");
	m = sp_match_out(d, (const struct rte_ipv4_hdr *)pkt, sizeof(pkt), &ds);
	CHECK(m && m->slid == 77 && ds && ds->spi == 0x3001, "bind: back to the PROTECT policy");

	mk_sa(&r, 0x3001, "192.0.2.21", "192.0.2.22");
	sa_install(d, &r, NULL, 0, 1, 0);
	spd_teardown(d);
}

/* Differential test: the rte_acl SPD must pick exactly the policy a full
 * scan picks (r2dp_sel_match, highest r2dp_sel_score, lowest slot on a tie)
 * for random policies and packets, incl. ports, protocols, fragments,
 * truncated L4, IP options and unmatchable (non-IPv4 / pref > 32) rules. */
static uint32_t rnd_state = 0x12345678;
static uint32_t rnd(void) { rnd_state ^= rnd_state << 13; rnd_state ^= rnd_state >> 17; rnd_state ^= rnd_state << 5; return rnd_state; }

static const struct r2dp_sp *
ref_match(struct dpdk_priv *d, const uint8_t *ip, size_t avail)
{
	const struct r2dp_sp *best = NULL;
	int bs = -1;

	for (int i = 0; i < (int)sp_cap(d); i++) {
		const struct r2dp_sp *sp = (*sp_at(d, (uint32_t)(i))).sp;
		int sc;
		if (!sp || sp->dir != R2DP_DIR_OUT || !r2dp_sel_match(sp, ip, avail))
			continue;
		sc = r2dp_sel_score(sp);
		if (sc > bs) { bs = sc; best = sp; }
	}
	return best;
}

static void
t_acl_diff(struct dpdk_priv *d)
{
	struct fwd_dp dp = { .priv = d };
	static const uint8_t protos[] = { R2DP_PROTO_ANY, 6, 17, 1, 132 };
	static const uint16_t ports[] = { 0, 53, 80, 443 };
	unsigned mism = 0, matched = 0, nomatch = 0, npk = 30000;

	static uint8_t bip[BURST_SZ][64];
	static const struct r2dp_sp *bwant[BURST_SZ];
	unsigned bn = 0, bmism = 0;
	size_t bav[BURST_SZ];

	/* Check after every 10 policy changes, so the classifier is seen
	 * fresh, reused with a delta list, with dead rules (deleted/replaced
	 * policies), and right after a compaction. */
	for (int round = 0; round < 30; round++) {
		for (int i = 0; i < 10; i++) {
			struct r2dp_sp sp;
			memset(&sp, 0, sizeof(sp));
			sp.slid = 5000 + (rnd() % 260);           /* some upserts */
			sp.dir = (rnd() % 5) ? R2DP_DIR_OUT : R2DP_DIR_IN;
			sp.action = 1 + rnd() % 3;
			sp.ul_proto = protos[rnd() % 5];
			sp.sel_src.family = (rnd() % 40) ? R2DP_AF_INET4 : R2DP_AF_INET6;
			sp.sel_dst.family = R2DP_AF_INET4;
			sp.sel_src.addr[0] = sp.sel_dst.addr[0] = 10;
			sp.sel_src.addr[1] = rnd() % 4; sp.sel_src.addr[2] = rnd() % 4; sp.sel_src.addr[3] = rnd() % 4;
			sp.sel_dst.addr[1] = rnd() % 4; sp.sel_dst.addr[2] = rnd() % 4; sp.sel_dst.addr[3] = rnd() % 4;
			sp.pref_src = (uint8_t)(8 + rnd() % 26);   /* 33: unmatchable; >= 8 so */
			sp.pref_dst = (uint8_t)(8 + rnd() % 25);   /* 11/8 packets miss */
			sp.sel_src.port = htons(ports[rnd() % 4] * (rnd() % 3 == 0));
			sp.sel_dst.port = htons(ports[rnd() % 4] * (rnd() % 2));
			sp.tun_src.family = sp.tun_dst.family = R2DP_AF_INET4;
			if (dpd_sp_add(&dp, &sp) != 0) { CHECK(0, "acl-diff: sp_add"); return; }
			if (rnd() % 4 == 0) { sp.slid = 5000 + (rnd() % 260); dpd_sp_del(&dp, &sp); }
		}
		if (round % 7 == 6)
			spd_rebuild_ex(d, 2);             /* idle compaction */
		for (unsigned n = 0; n < npk / 30; n++) {
			uint8_t ip[64];
			size_t ihl = (rnd() % 8) ? 20 : 24, avail;
			const struct r2dp_sp *want, *got;
			struct dp_sa *ds;
			uint16_t sp_, dp_;

			memset(ip, 0, sizeof(ip));
			ip[0] = 0x40 | (uint8_t)(ihl / 4);
			ip[9] = protos[1 + rnd() % 4];
			if (rnd() % 6 == 0) { ip[6] = 0x00; ip[7] = (uint8_t)(1 + rnd() % 8); }  /* non-first frag */
			if (rnd() % 9 == 0) ip[6] = 0x20;                                      /* MF, first frag */
			ip[12] = ip[16] = 10;
			if (rnd() % 6 == 0) ip[12 + 4 * (rnd() % 2)] = 11;  /* no-match share */
			for (int k = 1; k < 4; k++) { ip[12 + k] = rnd() % 4; ip[16 + k] = rnd() % 4; }
			sp_ = htons(ports[rnd() % 4] ? ports[rnd() % 4] : 1234);
			dp_ = htons(ports[rnd() % 4] ? ports[rnd() % 4] : 4321);
			memcpy(ip + ihl, &sp_, 2); memcpy(ip + ihl + 2, &dp_, 2);
			avail = (rnd() % 10) ? ihl + 8 : ihl + 2;                    /* truncated L4 */
			want = ref_match(d, ip, avail);
			got = sp_match_out(d, (const struct rte_ipv4_hdr *)ip, avail, &ds);
			if (want) matched++; else nomatch++;
			/* the burst classifier must agree packet for packet */
			memcpy(bip[bn], ip, sizeof(ip));
			bav[bn] = avail;
			bwant[bn++] = got;
			if (n % 3 == 0) {        /* same key twice in a row: shared result */
				memcpy(bip[bn], ip, sizeof(ip));
				bav[bn] = avail;
				bwant[bn++] = got;
			}
			if (bn >= BURST_SZ - 1 || n + 1 == npk / 30) {
				const struct rte_ipv4_hdr *bp[BURST_SZ];
				const struct r2dp_sp *bgot[BURST_SZ];
				struct dp_sa *bds[BURST_SZ];
				for (unsigned b = 0; b < bn; b++)
					bp[b] = (b % 7 == 3) ? NULL : (const struct rte_ipv4_hdr *)bip[b];
				sp_match_out_burst(d, bp, bav, (uint16_t)bn, bgot, bds);
				for (unsigned b = 0; b < bn; b++)
					if (bgot[b] != (bp[b] ? bwant[b] : NULL))
						bmism++;
				bn = 0;
			}
			if (want != got) {
				if (mism++ < 5)
					printf("     mismatch pkt %u: want slid %u got slid %u\n", n,
					    want ? want->slid : 0, got ? got->slid : 0);
			}
		}
	}
	printf("     acl-diff: %u packets, %u matched, %u matched none\n", npk, matched, nomatch);
	CHECK(bmism == 0, "acl-diff: sp_match_out_burst == sp_match_out");
	CHECK(mism == 0 && matched > npk / 4 && nomatch > npk / 20, "acl-diff: rte_acl SPD == full scan on random policies/packets");
	printf("     acl-diff: %llu classifier builds, %llu reuses\n",
	    (unsigned long long)d->n_acl_build, (unsigned long long)d->n_acl_reuse);
	CHECK(d->n_acl_reuse > d->n_acl_build, "acl-diff: classifier reused across policy changes");
	spd_teardown(d);
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
		CHECK(dp_sad_lookup(d->sad, kp, val, 1) == 1 && val[0] != NULL,
		    "SAD resolves the fresh inbound SA");
		CHECK(val[0] && ((struct dp_sa *)((char *)val[0] -
		    offsetof(struct dp_sa, sess)))->inbound == 1, "SA marked inbound");

		/* upsert (same SPI/DIP): the old slot is retired, new one live */
		CHECK(sa_install(d, &r, key, 20, 0, 1) == 0, "inbound upsert");
		CHECK(d->rcu_tid == canary_tid, "upsert leaves canary intact");
		CHECK(dp_sad_lookup(d->sad, kp, val, 1) == 1 && val[0] != NULL,
		    "SAD resolves the upserted SA");
		CHECK(sa_install(d, &r, NULL, 0, 1, 1) == 0, "inbound delete");
		CHECK(dp_sad_lookup(d->sad, kp, val, 1) == 0,
		    "SAD empty after delete");
	}

	/* key blob must match enckeylen + authkeylen exactly */
	mk_sa(&r, 0x1101, "192.0.2.2", "192.0.2.1");
	CHECK(sa_install(d, &r, key, 19, 0, 1) == -EINVAL, "short key blob refused");
	CHECK(sa_install(d, &r, NULL, 0, 0, 1) == -EINVAL, "missing key blob refused");

	/* --- 2. sa_by_policy prefers the newest outbound SA --- */
	{
		struct dp_sa *pick;
		int old_slot = -1, new_slot = -1;

		mk_sa(&r, 0x2001, "192.0.2.1", "192.0.2.2");      /* old SA */
		CHECK(sa_install(d, &r, key, 20, 0, 0) == 0, "outbound SA #1");
		mk_sa(&r, 0x2002, "192.0.2.1", "192.0.2.2");      /* rekeyed SA */
		CHECK(sa_install(d, &r, key, 20, 0, 0) == 0, "outbound SA #2");
		for (int i = 0; i < (int)sa_cap(d); i++) {
			if (!(*sa_at(d, (uint32_t)(i))).used) continue;
			if ((*sa_at(d, (uint32_t)(i))).spi == 0x2001) old_slot = i;
			if ((*sa_at(d, (uint32_t)(i))).spi == 0x2002) new_slot = i;
		}
		/* force the OLD SA into a later slot than the new one, so a
		 * "last matching slot" policy would pick the wrong SA */
		if (old_slot >= 0 && new_slot >= 0 && old_slot < new_slot) {
			struct dp_sa t = *sa_at(d, (uint32_t)old_slot);
			*sa_at(d, (uint32_t)old_slot) = *sa_at(d, (uint32_t)new_slot);
			*sa_at(d, (uint32_t)new_slot) = t;
			sa_at(d, (uint32_t)old_slot)->idx = (uint32_t)old_slot;
			sa_at(d, (uint32_t)new_slot)->idx = (uint32_t)new_slot;
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
	t_sad(d);
	t_inbound_policy(d);
	t_binding(d);
	t_replay_window();
	t_replay_diff();
	t_wsize_install(d);
	t_inbound_indexed(d);
	t_acl_diff(d);

	/* teardown: free every session (no leaks under LSan) */
	for (int i = 0; i < (int)sa_cap(d); i++)
		if ((*sa_at(d, (uint32_t)(i))).used)
			sa_slot_free(d, &(*sa_at(d, (uint32_t)(i))));
	dp_sad_destroy(d->sad);
	rte_mempool_free(d->sess_mp);
	rte_cryptodev_stop(d->cdev_id);
	rte_cryptodev_close(d->cdev_id);
	spd_teardown(d);
	dp_tables_free(d);
	free(d);
	rte_eal_cleanup();

	if (fails) { printf("dp_sa: %d failures\n", fails); return 1; }
	puts("dp_sa: OK");
	return 0;
}

/*
 * nh_tab: the DPDK next-hop table (fwd/dpdk_nh.c), N1/N2 and growth:
 *   - learn / unchanged / relearn on MAC change (in place), unknown peer ->
 *     miss (the caller drops, never broadcasts), explicit delete;
 *   - well past the old 64-peer limit: 65 and 1000 peers learned into a
 *     tiny table, all found by the per-burst bulk lookup;
 *   - growth under traffic: from 8 slots to 10000 peers while reader
 *     lcores bulk-look-up every peer already learned, under the QSBR the
 *     retired tables are freed through -- zero misses (no next-hop drop),
 *     every hit its own peer's MAC (no torn word, no freed table read);
 *   - allocation failure during growth: the table in service keeps every
 *     entry, new peers wait on the pending list, and all land once growth
 *     succeeds.  Nothing is ever evicted.
 * Run under ASan too.  Exit 77 (skip) without EAL or lcores unless
 * R2DP_REQUIRE_DPDK=1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_rcu_qsbr.h>

#include "dpdk_nh.h"

#define NR      3             /* reader lcores */
#define NGROW   10000u
#define BASE    0x0a000000u

static int fails;
#define CHECK(c, m) do { if (c) printf("ok   %s\n", m); \
	else { printf("FAIL %s\n", m); fails++; } } while (0)

/* each peer's MAC is a function of its address, so a reader can tell */
static void
mac_of(uint32_t ip, uint8_t m[6])
{
	m[0] = 0x02;
	memcpy(m + 1, &ip, 4);
	m[5] = (uint8_t)(ip * 31 + 7);
}

static uint64_t
word_of(uint32_t ip)
{
	uint64_t w = 0;
	uint8_t m[6];

	mac_of(ip, m);
	memcpy(&w, m, 6);
	return w;
}

static struct rte_rcu_qsbr *rcu;

/* learn and, with no maintenance thread, run passes until it is in */
static int
learn_sync(struct r2dp_nh_tab *t, uint32_t ip)
{
	uint8_t m[6], mo[6];

	mac_of(ip, m);
	for (int i = 0; i < 100; i++) {
		if (r2dp_nh_learn(t, ip, m) < 0)
			continue;
		if (r2dp_nh_lookup(t, ip, mo) && !memcmp(mo, m, 6))
			return 0;
		r2dp_nh_maint(t);
	}
	return -1;
}

static unsigned
bulk_found(struct r2dp_nh_tab *t, uint32_t base, unsigned n)
{
	unsigned found = 0;

	for (unsigned i = 0; i < n; i += 32) {
		uint32_t ip[32];
		uint64_t mac[32], hit;
		unsigned k = n - i < 32 ? n - i : 32;
		for (unsigned j = 0; j < k; j++)
			ip[j] = base + i + j;
		hit = r2dp_nh_lookup_bulk(t, ip, k, mac);
		for (unsigned j = 0; j < k; j++)
			if ((hit >> j & 1) &&
			    (mac[j] & 0xffffffffffffull) == word_of(ip[j]))
				found++;
	}
	return found;
}

static void
basic(void)
{
	struct r2dp_nh_tab t;
	const uint8_t p1[6] = { 0x02, 0, 0, 0, 0, 2 };
	const uint8_t p2[6] = { 0x02, 0, 0, 0, 0, 3 };
	uint8_t mo[6];

	CHECK(r2dp_nh_init(&t, "nh_basic", 0, NULL, SOCKET_ID_ANY) == 0 &&
	    t.cap == R2DP_NH_DEFAULT_SIZE, "default-size table");
	CHECK(r2dp_nh_lookup(&t, 7, mo) == 0, "unknown peer -> miss (drop)");
	CHECK(r2dp_nh_learn(&t, 7, p1) == 1, "learn new peer");
	CHECK(r2dp_nh_learn(&t, 7, p1) == 0, "same MAC unchanged");
	CHECK(r2dp_nh_lookup(&t, 7, mo) && !memcmp(mo, p1, 6), "lookup peer");
	CHECK(r2dp_nh_learn(&t, 8, p2) == 1, "second peer keyed separately");
	CHECK(r2dp_nh_lookup(&t, 7, mo) && !memcmp(mo, p1, 6),
	    "first peer unaffected by second");
	CHECK(r2dp_nh_learn(&t, 7, p2) == 2 && t.n == 2, "relearn on MAC change, in place");
	CHECK(r2dp_nh_lookup(&t, 7, mo) && !memcmp(mo, p2, 6),
	    "lookup returns relearned MAC");
	CHECK(r2dp_nh_del(&t, 7) == 1 && !r2dp_nh_lookup(&t, 7, mo) &&
	    r2dp_nh_lookup(&t, 8, mo) && t.n == 1, "explicit delete removes only that peer");
	r2dp_nh_free(&t);
}

static void
many(unsigned n)
{
	struct r2dp_nh_tab t;
	char name[32], msg[96];
	int r = 0;

	snprintf(name, sizeof(name), "nh_many%u", n);
	if (r2dp_nh_init(&t, name, 8, rcu, SOCKET_ID_ANY)) {
		CHECK(0, "table init");
		return;
	}
	for (unsigned i = 0; i < n; i++)
		r |= learn_sync(&t, 5000 + i);
	r2dp_nh_maint(&t);
	snprintf(msg, sizeof(msg), "%u peers learned from an 8-slot table "
	    "(cap now %u, %llu grows)", n, t.cap, (unsigned long long)t.n_grow);
	CHECK(!r && t.n == n && t.npend == 0, msg);
	snprintf(msg, sizeof(msg), "bulk lookup finds all %u peers", n);
	CHECK(bulk_found(&t, 5000, n) == n, msg);
	r2dp_nh_free(&t);
}

/* ---- growth under concurrent traffic ---- */
static struct r2dp_nh_tab gt;
static uint32_t learned;            /* peers [0, learned) are in */
static volatile int stop;
static uint64_t r_hits[RTE_MAX_LCORE], r_miss[RTE_MAX_LCORE],
    r_bad[RTE_MAX_LCORE];

static int
reader(void *arg)
{
	unsigned me = rte_lcore_id();
	uint32_t ip[32];
	uint64_t mac[32], x = me * 7919u + 1;

	(void)arg;
	rte_rcu_qsbr_thread_register(rcu, me);
	rte_rcu_qsbr_thread_online(rcu, me);
	while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE)) {
		uint32_t n = __atomic_load_n(&learned, __ATOMIC_ACQUIRE);
		uint64_t hit;
		if (!n) {
			rte_rcu_qsbr_quiescent(rcu, me);
			continue;
		}
		for (unsigned i = 0; i < 32; i++) {
			x = x * 6364136223846793005ull + 1442695040888963407ull;
			ip[i] = BASE + (uint32_t)(x >> 33) % n;
		}
		hit = r2dp_nh_lookup_bulk(&gt, ip, 32, mac);
		for (unsigned i = 0; i < 32; i++)
			if (!(hit >> i & 1))
				r_miss[me]++;
			else {
				r_hits[me]++;
				if ((mac[i] & 0xffffffffffffull) != word_of(ip[i]))
					r_bad[me]++;
			}
		rte_rcu_qsbr_quiescent(rcu, me);
	}
	rte_rcu_qsbr_thread_offline(rcu, me);
	rte_rcu_qsbr_thread_unregister(rcu, me);
	return 0;
}

static void
grow_under_traffic(void)
{
	unsigned lc, nl = 0, me = rte_lcore_id();
	uint64_t hits = 0, miss = 0, bad = 0, queued = 0;
	char msg[128];
	int stuck = 0;

	if (r2dp_nh_init(&gt, "nh_grow", 8, rcu, SOCKET_ID_ANY) ||
	    r2dp_nh_start(&gt)) {
		CHECK(0, "table init");
		return;
	}
	RTE_LCORE_FOREACH_WORKER(lc) {
		if (nl == NR)
			break;
		rte_eal_remote_launch(reader, NULL, lc);
		nl++;
	}
	/* the learner is a QSBR reader too, like the dispatcher lcore */
	rte_rcu_qsbr_thread_register(rcu, me);
	rte_rcu_qsbr_thread_online(rcu, me);
	for (uint32_t i = 0; i < NGROW && !stuck; i++) {
		uint32_t ip = BASE + i;
		uint8_t m[6], mo[6];
		uint64_t tries = 0, t0 = rte_get_timer_cycles();
		mac_of(ip, m);
		for (;;) {
			/* a peer re-offers itself with its next frame, not on
			 * every spin */
			if (tries % 65536 == 0)
				queued += r2dp_nh_learn(&gt, ip, m) == 4;
			rte_rcu_qsbr_quiescent(rcu, me);
			if (r2dp_nh_lookup(&gt, ip, mo))
				break;
			if (rte_get_timer_cycles() - t0 > 5 * rte_get_timer_hz()) {
				stuck = 1;   /* 5 s: the learn was lost */
				break;
			}
			tries++;
			rte_pause();
		}
		if (stuck)
			break;
		__atomic_store_n(&learned, i + 1, __ATOMIC_RELEASE);
	}
	/* let the readers run over the final table a little */
	for (int i = 0; i < 2000; i++) {
		rte_rcu_qsbr_quiescent(rcu, me);
		usleep(100);
	}
	rte_rcu_qsbr_thread_offline(rcu, me);
	rte_rcu_qsbr_thread_unregister(rcu, me);
	__atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
	rte_eal_mp_wait_lcore();
	r2dp_nh_stop(&gt);
	for (unsigned i = 0; i < RTE_MAX_LCORE; i++) {
		hits += r_hits[i];
		miss += r_miss[i];
		bad += r_bad[i];
	}
	printf("     grow: %u readers, %llu hits, %llu misses, cap %u after "
	    "%llu grows (%llu failed), %llu learns queued, %llu refused\n", nl,
	    (unsigned long long)hits, (unsigned long long)miss, gt.cap,
	    (unsigned long long)gt.n_grow, (unsigned long long)gt.n_grow_fail,
	    (unsigned long long)queued, (unsigned long long)gt.n_q_drop);
	snprintf(msg, sizeof(msg), "8 -> %u peers learned while readers ran",
	    NGROW);
	CHECK(!stuck && gt.n == NGROW && bulk_found(&gt, BASE, NGROW) == NGROW,
	    msg);
	CHECK(nl == NR && hits > 0, "readers ran and hit");
	CHECK(miss == 0, "zero next-hop misses for learned peers during growth");
	CHECK(bad == 0, "every hit carried its own peer's MAC");
	CHECK(gt.n_grow >= 10 && gt.n_grow_fail == 0 && gt.n_q_drop == 0,
	    "table grew repeatedly, no failures, nothing refused");
	r2dp_nh_free(&gt);
}

static void
grow_alloc_failure(void)
{
	struct r2dp_nh_tab t;
	uint8_t m[6];
	unsigned in, want = 64;
	char msg[128];

	if (r2dp_nh_init(&t, "nh_afail", 8, rcu, SOCKET_ID_ANY)) {
		CHECK(0, "table init");
		return;
	}
	t.inject_grow_fail = ~0u;               /* every growth attempt fails */
	for (unsigned i = 0; i < want; i++) {
		mac_of(BASE + i, m);
		r2dp_nh_learn(&t, BASE + i, m);
		r2dp_nh_maint(&t);
	}
	in = t.n;
	snprintf(msg, sizeof(msg), "growth failing: table keeps serving its %u "
	    "peers, %u pending, %llu failed growths", in, t.npend,
	    (unsigned long long)t.n_grow_fail);
	CHECK(in >= 6 && t.n_grow_fail > 0 && t.cap == 8 &&
	    in + t.npend == want, msg);
	CHECK(bulk_found(&t, BASE, want) == in, "every entry in the table still "
	    "found (nothing evicted)");
	{
		/* the first `in` learned are exactly the ones in the table */
		unsigned ok = 1;
		for (unsigned i = 0; i < in; i++)
			ok &= bulk_found(&t, BASE + i, 1) == 1;
		CHECK(ok, "earliest peers kept forwarding");
	}
	t.inject_grow_fail = 0;                 /* memory is back */
	r2dp_nh_maint(&t);
	r2dp_nh_maint(&t);
	r2dp_nh_maint(&t);
	CHECK(t.npend == 0 && t.n == want && bulk_found(&t, BASE, want) == want,
	    "after recovery every pending peer landed");
	r2dp_nh_free(&t);
}

int
main(void)
{
	char *ea[] = { "nh_tab", "-l", "0-3", "--no-huge", "-m", "256",
	    "--no-pci", "--no-telemetry", "--log-level=1", NULL };
	size_t sz;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (rte_eal_init(9, ea) < 0 || rte_lcore_count() < NR + 1) {
		if (getenv("R2DP_REQUIRE_DPDK")) { puts("DPDK setup FAILED"); return 1; }
		puts("SKIP: EAL/lcores"); return 77;
	}
	sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	rcu = rte_zmalloc("nh_rcu", sz, RTE_CACHE_LINE_SIZE);
	if (!rcu || rte_rcu_qsbr_init(rcu, RTE_MAX_LCORE)) {
		puts("FAIL rcu"); return 1;
	}
	basic();
	many(65);
	many(1000);
	grow_alloc_failure();
	grow_under_traffic();
	rte_free(rcu);
	rte_eal_cleanup();
	if (fails) { printf("nh_tab: %d failures\n", fails); return 1; }
	puts("nh_tab: OK");
	return 0;
}

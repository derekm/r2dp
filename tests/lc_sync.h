/* Launch/wait wrappers that make EAL's lcore hand-off visible to
 * ThreadSanitizer: librte_eal is not instrumented, so the ordering that
 * rte_eal_remote_launch / rte_eal_mp_wait_lcore provide is invisible to
 * it.  An acquire/release pair around each launched function restores
 * those edges; behaviour is unchanged. */
#ifndef R2DP_TESTS_LC_SYNC_H
#define R2DP_TESTS_LC_SYNC_H
#include <rte_launch.h>
#include <rte_lcore.h>

static struct {
	lcore_function_t *f;
	void *a;
	int start, done;
} lc_sync_t[RTE_MAX_LCORE];

static int
lc_sync_tramp(void *p)
{
	unsigned lc = rte_lcore_id();
	int r;
	(void)p;
	(void)__atomic_load_n(&lc_sync_t[lc].start, __ATOMIC_ACQUIRE);
	r = lc_sync_t[lc].f(lc_sync_t[lc].a);
	__atomic_store_n(&lc_sync_t[lc].done, 1, __ATOMIC_RELEASE);
	return r;
}

static inline int
lc_launch(lcore_function_t *f, void *a, unsigned lc)
{
	lc_sync_t[lc].f = f;
	lc_sync_t[lc].a = a;
	lc_sync_t[lc].done = 0;
	__atomic_store_n(&lc_sync_t[lc].start, 1, __ATOMIC_RELEASE);
	return rte_eal_remote_launch(lc_sync_tramp, NULL, lc);
}

static inline void
lc_wait_all(void)
{
	unsigned lc;
	rte_eal_mp_wait_lcore();
	RTE_LCORE_FOREACH_WORKER(lc)
		(void)__atomic_load_n(&lc_sync_t[lc].done, __ATOMIC_ACQUIRE);
}
#endif

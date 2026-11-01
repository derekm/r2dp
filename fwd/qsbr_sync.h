/* rte_rcu_qsbr_synchronize(v, RTE_QSBR_THRID_INVALID), written out with
 * the inline start/check pair so that the acquire loads which order the
 * free after every reader's quiescent store are compiled into this
 * (instrumentable) code rather than hidden in librte_rcu: identical
 * behaviour, and ThreadSanitizer sees the grace period. */
#ifndef R2DP_QSBR_SYNC_H
#define R2DP_QSBR_SYNC_H
#include <stdbool.h>
#include <rte_pause.h>
#include <rte_rcu_qsbr.h>

static inline void
r2dp_qsbr_sync(struct rte_rcu_qsbr *v)
{
	uint64_t t = rte_rcu_qsbr_start(v);

	while (rte_rcu_qsbr_check(v, t, false) != 1)
		rte_pause();
}
#endif

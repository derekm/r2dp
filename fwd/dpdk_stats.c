/*
 * fwd/dpdk_stats.c -- DPDK data plane: counters and their dump.
 */
#ifdef R2DP_HAVE_DPDK

#include "dpdk_int.h"

const char *const dp_drop_name[DR_NUM] = {
	"malformed", "no_sa_in", "no_sa_out", "policy_discard", "inner_sel",
	"crypto_fail", "replay", "ipsec_reject", "crypto_enq", "nomem", "no_nexthop",
	"clear_outer", "esp_on_inner", "tx_full", "crypto_stuck",
	"encap",
};


/* One-shot stats dump (SIGUSR1 -> fwd_stats_req, read by the worker). */
void
dpd_stats_dump(struct dpdk_priv *d, FILE *f)
{
	fprintf(f, "r2dp-fwd: stats rx=%llu tx=%llu esp=%llu ike=%llu drop=%llu "
	    "spd_fail=%llu\n", (unsigned long long)d->n_rx,
	    (unsigned long long)d->n_tx, (unsigned long long)d->n_esp,
	    (unsigned long long)d->n_ike, (unsigned long long)d->n_drop,
	    (unsigned long long)d->n_spd_fail);
	fprintf(f, "r2dp-fwd: drops");
	for (int r = 0; r < DR_NUM; r++)
		fprintf(f, " %s=%llu", dp_drop_name[r],
		    (unsigned long long)d->n_dropr[r]);
	fprintf(f, " (crypto_stuck_events=%llu outstanding=%u natt_keepalive=%llu)",
	    (unsigned long long)d->n_crypto_stuck, d->cq_stale,
	    (unsigned long long)d->n_natt_keepalive);
	fprintf(f, "\n");
	fflush(f);
}



#endif /* R2DP_HAVE_DPDK */

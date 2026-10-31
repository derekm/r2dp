/*
 * fwd/dpdk_stats.c -- DPDK data plane: counters and their dump.
 */
#ifdef R2DP_HAVE_DPDK

#include "dpdk_int.h"

const char *const dp_drop_name[DR_NUM] = {
	"malformed", "no_sa_in", "no_sa_out", "policy_discard", "inner_sel",
	"crypto_fail", "replay", "ipsec_reject", "crypto_enq", "nomem", "no_nexthop",
	"clear_outer", "esp_on_inner", "tx_full", "crypto_stuck",
	"encap", "steer",
};


/* Sum of every worker's (and the dispatcher's) counters. */
void
dpd_stats_sum(const struct dpdk_priv *d, struct dp_wk *t)
{
	memset(t, 0, sizeof(*t));
	for (unsigned i = 0; i <= d->nb_wk && i <= DP_MAX_WK; i++) {
		const struct dp_wk *w = &d->wk[i];
		t->n_rx += w->n_rx;
		t->n_tx += w->n_tx;
		t->n_esp += w->n_esp;
		t->n_ike += w->n_ike;
		t->n_drop += w->n_drop;
		for (int r = 0; r < DR_NUM; r++)
			t->n_dropr[r] += w->n_dropr[r];
		t->cq_stale += w->cq_stale;
		t->n_crypto_stuck += w->n_crypto_stuck;
		t->n_natt_keepalive += w->n_natt_keepalive;
	}
}

/* One-shot stats dump (SIGUSR1 -> fwd_stats_req).  Counters are read
 * without synchronisation from other workers: a dump is a snapshot, each
 * 64-bit load is atomic on the targets we build for. */
void
dpd_stats_dump(struct dpdk_priv *d, FILE *f)
{
	struct dp_wk t;

	dpd_stats_sum(d, &t);
	fprintf(f, "r2dp-fwd: stats rx=%llu tx=%llu esp=%llu ike=%llu drop=%llu "
	    "spd_fail=%llu\n", (unsigned long long)t.n_rx,
	    (unsigned long long)t.n_tx, (unsigned long long)t.n_esp,
	    (unsigned long long)t.n_ike, (unsigned long long)t.n_drop,
	    (unsigned long long)d->n_spd_fail);
	fprintf(f, "r2dp-fwd: drops");
	for (int r = 0; r < DR_NUM; r++)
		fprintf(f, " %s=%llu", dp_drop_name[r],
		    (unsigned long long)t.n_dropr[r]);
	fprintf(f, " (crypto_stuck_events=%llu outstanding=%u natt_keepalive=%llu)",
	    (unsigned long long)t.n_crypto_stuck, t.cq_stale,
	    (unsigned long long)t.n_natt_keepalive);
	fprintf(f, "\n");
	if (d->nb_wk > 1)
		for (unsigned i = 0; i <= d->nb_wk; i++)
			fprintf(f, "r2dp-fwd: %s %u: rx=%llu tx=%llu esp=%llu "
			    "drop=%llu\n", i < d->nb_wk ? "worker" : "dispatcher", i,
			    (unsigned long long)d->wk[i].n_rx,
			    (unsigned long long)d->wk[i].n_tx,
			    (unsigned long long)d->wk[i].n_esp,
			    (unsigned long long)d->wk[i].n_drop);
	fflush(f);
}

#endif /* R2DP_HAVE_DPDK */

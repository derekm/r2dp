/*
 * fwd/dp.c -- dataplane defaults + the no-DPDK fallback for
 * fwd_dp_dpdk_probe.  Real DPDK backend lives in dp_dpdk.c (built only
 * when the enable_dpdk meson opt is on).  When DPDK is absent this file
 * supplies a control-only probe so r2dp-fwd still serves the r2dp socket.
 */
#include <string.h>

#include "dp.h"

volatile sig_atomic_t fwd_stats_req;

#ifndef R2DP_HAVE_DPDK
#include <errno.h>
int
fwd_dp_dpdk_probe(struct fwd_dp *dp, int *argc, char **argv[],
    const char *sockpath, int verbose, int nb_workers)
{
	(void)dp; (void)argc; (void)argv; (void)sockpath; (void)verbose;
	(void)nb_workers;
	return -2;      /* "no DPDK build" */
}
#endif

void
fwd_dp_init(struct fwd_dp *dp)
{
	memset(dp, 0, sizeof(*dp));
	dp->ops = NULL;
}

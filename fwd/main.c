/*
 * r2dp-fwd: the r2dp forwarder daemon.
 *
 * M1 scope: serves the r2dp control-plane socket (fwd/ctl.c) and applies
 * SAD/SPD to a DPDK dataplane (fwd/dp_dpdk.c, compiled in when built with
 * DPDK).  Without DPDK the process still runs as a protocol-faithful
 * control server (no forwarding), which is the M0-mock equivalent for
 * driving racoon2 and the test suite.
 *
 * Usage:
 *   r2dp-fwd [-s sockpath] [-v] [-n workers] [--dp dpdk|kernel] [EAL args]
 *
 * -n: DPDK packet workers (default 1).  With more than one, an extra lcore
 * dispatches packets to the worker owning each tunnel, so give the EAL
 * -n + 2 lcores (main + dispatcher + workers), e.g. -n 2 -l 0-3.
 */
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ctl.h"
#include "dp.h"

#ifndef R2DP_DEFAULT_SOCK
#define R2DP_DEFAULT_SOCK "/run/r2dp/r2dp.sock"
#endif

static struct fwd_ctl ctl;
static volatile sig_atomic_t g_stop;

static void on_sig(int s) { (void)s; g_stop = 1; }
static void on_usr1(int s) { (void)s; fwd_stats_req = 1; }

int
main(int argc, char **argv)
{
	const char *sockpath = getenv("R2DP_SOCK");
	int verbose = 0;
	const char *dpname = "dpdk";   /* --dp dpdk|kernel */
	int dp_cleanup = 0;
	int nb_workers = 1;
	/* DPDK EAL args (everything not one of our own) go to rte_eal_init */
	char **eal_argv, **eal_base;
	int eal_argc = 1, i;

	if (!sockpath || !*sockpath)
		sockpath = R2DP_DEFAULT_SOCK;

	eal_argv = calloc((size_t)argc + 1, sizeof(char *));
	if (!eal_argv)
		return 1;
	eal_base = eal_argv;      /* rte_eal_init advances *argv; free the base */
	eal_argv[0] = argv[0];    /* EAL expects argv[0] = program name; rest at 1 */

	/* Manual parse: keep -s/-v/-n for the control server, pass everything
	 * else (DPDK EAL opts like --vdev/--no-pci/--huge-dir, and their
	 * operands) to rte_eal_init.  Stops at the first bare operand. */
	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "-s") == 0 && i + 1 < argc) {
			sockpath = argv[++i];
		} else if (strcmp(a, "-v") == 0) {
			verbose = 1;
		} else if (strcmp(a, "--dp") == 0 && i + 1 < argc) {
			dpname = argv[++i];
		} else if (strcmp(a, "--dp-cleanup") == 0) {
			dp_cleanup = 1;
		} else if (strcmp(a, "-n") == 0 && i + 1 < argc) {
			nb_workers = atoi(argv[++i]);   /* DPDK packet workers */
		} else {
			eal_argv[eal_argc++] = argv[i];
		}
	}

	signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGPIPE, SIG_IGN);
	signal(SIGUSR1, on_usr1);   /* dump datapath stats + drop reasons */

	fwd_ctl_init(&ctl, sockpath, verbose);

	if (strcmp(dpname, "kernel") == 0) {
		/* Linux XFRM data plane: a kernel that cannot hold any ESP state
		 * is fatal here -- the operator asked for this backend. */
		int r = fwd_dp_xfrm_probe(&ctl.dp, verbose, dp_cleanup);
		if (r < 0) {
			fprintf(stderr, "r2dp-fwd: kernel XFRM dataplane: %s\n",
			    strerror(-r));
			free(eal_base);
			return 1;
		}
	} else if (strcmp(dpname, "dpdk") != 0) {
		fprintf(stderr, "r2dp-fwd: --dp dpdk|kernel (got '%s')\n", dpname);
		free(eal_base);
		return 2;
	} else
	/* Optional DPDK dataplane probe.  Failure is non-fatal: we still serve
	 * the control socket (racoon2 bring-up + M0 tests). */
	{
		int r = fwd_dp_dpdk_probe(&ctl.dp, &eal_argc, &eal_argv,
		    sockpath, verbose, nb_workers);
		if (r < 0)
			fprintf(stderr, "r2dp-fwd: DPDK dataplane unavailable (%s); "
			    "serving control-only\n", r == -2 ? "no DPDK build" : strerror(-r));
		(void)g_stop;
	}
	free(eal_base);   /* rte_eal_init advanced eal_argv; free the calloc base */

	fwd_ctl_run(&ctl, sockpath);
	return 0;
}

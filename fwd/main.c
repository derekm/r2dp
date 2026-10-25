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
 *   r2dp-fwd [-s sockpath] [-v] [-n nprocessing_lcores]
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

int
main(int argc, char **argv)
{
	const char *sockpath = getenv("R2DP_SOCK");
	int verbose = 0, c;

	if (!sockpath || !*sockpath)
		sockpath = R2DP_DEFAULT_SOCK;

	while ((c = getopt(argc, argv, "s:vn:")) != -1) {
		switch (c) {
		case 's': sockpath = optarg; break;
		case 'v': verbose = 1; break;
		case 'n': break;   /* processing lcores; the DPDK probe claims it */
		default:
			fprintf(stderr, "usage: %s [-s sock] [-v] [-n ncores]\n", argv[0]);
			return 2;
		}
	}

	signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGPIPE, SIG_IGN);

	fwd_ctl_init(&ctl, sockpath, verbose);

	/* Optional DPDK dataplane probe.  Probe owns the EAL init and registers
	 * the dp vtable.  Failure to load DPDK is non-fatal: we still serve the
	 * control socket (useful for racoon2 bring-up and the M0 tests). */
	{
		int probe_argc = argc - optind;
		char **probe_argv = argv + optind;
		int r = fwd_dp_dpdk_probe(&ctl.dp, &probe_argc, &probe_argv,
		    sockpath, verbose);
		if (r < 0)
			fprintf(stderr, "r2dp-fwd: DPDK dataplane unavailable (%s); "
			    "serving control-only\n", r == -2 ? "no DPDK build" : strerror(-r));
		(void)g_stop;
	}

	fwd_ctl_run(&ctl, sockpath);
	return 0;
}

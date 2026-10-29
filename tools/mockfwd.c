/*
 * r2dp-mockfwd: protocol-faithful forwarder with no dataplane (control-plane
 * engine, no hooks).  Used for contract tests and to develop the racoon2 shim.
 *
 *   r2dp-mockfwd [-s sockpath] [-v] [-K] [-L]
 *     -v  log every request   -K  echo keys in completions (tests only)
 *     -L  enforce SA time lifetimes (soft/hard EXPIRE events to IKE clients)
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "r2dp/cp.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

int main(int argc, char **argv)
{
	struct r2dp_cp_opts o = { .name = "mockfwd" };
	const char *path = NULL;
	struct r2dp_srv *srv;
	struct r2dp_cp *cp;
	int c;

	while ((c = getopt(argc, argv, "s:vKL")) != -1) {
		switch (c) {
		case 's': path = optarg; break;
		case 'v': o.verbose = 1; break;
		case 'K': o.echo_keys = 1; break;
		case 'L': o.sw_lifetimes = 1; break;
		default: fprintf(stderr, "usage: %s [-s sock] [-v] [-K] [-L]\n", argv[0]); return 2;
		}
	}
	signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGPIPE, SIG_IGN);
	if (!(cp = r2dp_cp_new(NULL, NULL, &o))) return 1;
	if (!(srv = r2dp_srv_new(path))) { perror("mockfwd: listen"); return 1; }
	while (!stop) {
		if (r2dp_srv_poll(srv, cp, o.sw_lifetimes ? 250 : -1) < 0) break;
		r2dp_cp_tick(cp);
	}
	r2dp_srv_free(srv); r2dp_cp_free(cp);
	return 0;
}

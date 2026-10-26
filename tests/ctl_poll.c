/*
 * ctl_poll: regression test for the fwd_ctl_run accept/poll desync fixed in
 * 0bb71e1.  The control loop used to iterate clients up to the post-accept
 * count, reading a stale pf[] slot for a just-accepted fd; a stale
 * POLLIN/POLLHUP there drove a BLOCKING r2dp_recv on an idle client and froze
 * the whole control plane.
 *
 * Sequence that leaves a stale revent in pf[2] and then accepts into slot 1:
 *   A connects + HELLO (slot 0); B connects, HELLOs, closes (pf[2] = POLLHUP,
 *   B removed); C connects and stays idle (accepted into slot 1, pf[2] not
 *   rebuilt that pass).  A then issues requests; each must be answered
 *   within a bounded time.
 *
 * Usage: ctl_poll <path-to-r2dp-fwd>
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "r2dp/client.h"

static pid_t child = -1;
static char sockpath[128];

static void
stop_child(void)
{
	if (child > 0) {
		int st;
		kill(child, SIGTERM);
		waitpid(child, &st, 0);
		child = -1;
	}
	unlink(sockpath);
}

static int
connect_retry(void)
{
	int fd = -1;

	for (int i = 0; i < 200 && fd < 0; i++) {
		fd = r2dp_connect(sockpath);
		if (fd < 0)
			usleep(20000);
	}
	return fd;
}

/* HELLO with a bounded wait; returns 0 on a timely HELLO_ACK. */
static int
hello_timed(int fd, uint32_t seq)
{
	struct r2dp_hello h;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	struct r2dp_msg m;

	memset(&h, 0, sizeof(h));
	h.role = R2DP_ROLE_CTL;
	if (r2dp_send(fd, R2DP_HELLO, seq, 0, 0, &h, sizeof(h), NULL, 0) < 0)
		return -1;
	if (poll(&pfd, 1, 2000) != 1)
		return -ETIMEDOUT;
	if (r2dp_recv(fd, &m) < 0 || m.h.type != R2DP_HELLO_ACK || m.h.seq != seq)
		return -EPROTO;
	return 0;
}

int
main(int argc, char **argv)
{
	const char *bin = argc > 1 ? argv[1] : "r2dp-fwd";
	int a, b, c, fails = 0;

	signal(SIGPIPE, SIG_IGN);
	snprintf(sockpath, sizeof(sockpath), "/tmp/r2dp-ctlpoll-%ld.sock",
	    (long)getpid());
	unlink(sockpath);
	if ((child = fork()) < 0)
		return 2;
	if (child == 0) {
		execl(bin, bin, "-s", sockpath, (char *)NULL);
		_exit(127);
	}

	if ((a = connect_retry()) < 0) { stop_child(); return 1; }
	if (hello_timed(a, 1) != 0) { fprintf(stderr, "FAIL A hello\n"); fails++; }

	for (int round = 0; round < 5 && !fails; round++) {
		b = connect_retry();
		if (b < 0 || hello_timed(b, 2) != 0) {
			fprintf(stderr, "FAIL B hello (round %d)\n", round); fails++;
			break;
		}
		close(b);
		usleep(700000);          /* > one 500ms poll pass: B's HUP handled */
		c = connect_retry();     /* accepted into B's old slot, idle */
		usleep(700000);
		for (int k = 0; k < 3; k++)
			if (hello_timed(a, 10 + (uint32_t)k) != 0) {
				fprintf(stderr, "FAIL control loop stalled after idle "
				    "accept (round %d req %d)\n", round, k);
				fails++;
				break;
			}
		close(c);
		usleep(700000);
	}

	/* M8 send side: a client that floods requests and never reads must be
	 * dropped, not stall the loop for everyone else. */
	if (!fails) {
		int s = connect_retry(), dropped = 0;
		struct r2dp_hello h;
		memset(&h, 0, sizeof(h));
		fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
		for (int i = 0; i < 20000; i++)
			if (r2dp_send(s, R2DP_HELLO, (uint32_t)i, 0, 0, &h, sizeof(h),
			    NULL, 0) < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					usleep(1000);
				else { dropped = 1; break; }
			}
		if (hello_timed(a, 99) != 0) {
			fprintf(stderr, "FAIL loop stalled by a non-reading client\n");
			fails++;
		}
		/* drain: the forwarder must have hung up on the flooder */
		for (int i = 0; i < 400 && !dropped; i++) {
			char buf[R2DP_MAX_MSG];
			ssize_t n = recv(s, buf, sizeof(buf), 0);
			if (n == 0) dropped = 1;
			else if (n < 0 && errno != EAGAIN) dropped = 1;
			else if (n < 0) usleep(10000);
		}
		if (!dropped) {
			fprintf(stderr, "FAIL non-reading client was not dropped\n");
			fails++;
		}
		close(s);
	}

	close(a);
	stop_child();
	if (fails)
		return 1;
	printf("ctl_poll: OK (idle accept does not stall the control loop)\n");
	return 0;
}

/*
 * r2dp-kfwd: r2dp forwarder whose dataplane is the Linux kernel (XFRM).
 *
 * Every r2dp request is translated into NETLINK_XFRM and installed in the
 * kernel before the client is answered; the kernel's own errno is what the
 * client sees on refusal.  Use it as the reference/oracle when testing the
 * racoon2 shim or comparing behaviour with the DPDK forwarder (r2dp-fwd).
 * The kernel must be set up to forward (net.ipv4.ip_forward=1) for gateway use.
 *
 *   r2dp-kfwd [-s sockpath] [-v] [--io poll|uring] [--no-probe]
 *
 *   --io poll    (default) poll(2) loop, shared with the mock forwarder
 *   --io uring   EXPERIMENTAL: the control socket is served with io_uring
 *                (accept/recv as SQEs).  This only changes how *control*
 *                messages reach the engine.  Packets never leave the kernel
 *                in this backend, so io_uring cannot speed up the datapath.
 *   --no-probe   advertise every transform in the translation table instead of
 *                asking the kernel which ones it really supports at startup
 */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "r2dp/cp.h"
#include "xfrm.h"
#ifdef HAVE_LIBURING
#include <liburing.h>
#endif

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

#ifdef HAVE_LIBURING
/* ---------------------------------------------------------------- io_uring */
enum { OP_ACCEPT = 1, OP_RECV };

struct uconn {
	int op, fd;
	struct r2dp_msg msg;                    /* SOCK_SEQPACKET: one recv == one whole message */
};

static int arm_accept(struct io_uring *ring, int lfd)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	struct uconn *c;
	if (!sqe || !(c = calloc(1, sizeof(*c)))) return -ENOMEM;
	c->op = OP_ACCEPT; c->fd = lfd;
	io_uring_prep_accept(sqe, lfd, NULL, NULL, SOCK_CLOEXEC);
	io_uring_sqe_set_data(sqe, c);
	return 0;
}

static int arm_recv(struct io_uring *ring, struct uconn *c)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	if (!sqe) return -ENOMEM;
	c->op = OP_RECV;
	io_uring_prep_recv(sqe, c->fd, &c->msg, sizeof(c->msg), 0);
	io_uring_sqe_set_data(sqe, c);
	return 0;
}

static int serve_uring(const char *path, struct r2dp_cp *cp)
{
	struct io_uring ring;
	int lfd, r;

	if ((lfd = r2dp_listen(path, 8)) < 0) { fprintf(stderr, "kfwd: listen: %s\n", strerror(-lfd)); return 1; }
	if ((r = io_uring_queue_init(64, &ring, 0)) < 0) {
		fprintf(stderr, "kfwd: io_uring_queue_init: %s\n", strerror(-r)); close(lfd); return 1;
	}
	if (arm_accept(&ring, lfd) < 0) return 1;
	io_uring_submit(&ring);

	while (!stop) {
		struct io_uring_cqe *cqe;
		struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };   /* wake to check `stop` */
		struct uconn *c;
		int res;

		r = io_uring_wait_cqe_timeout(&ring, &cqe, &ts);
		if (r == -ETIME || r == -EINTR) continue;
		if (r < 0) { fprintf(stderr, "kfwd: io_uring_wait_cqe: %s\n", strerror(-r)); break; }
		c = io_uring_cqe_get_data(cqe);
		res = cqe->res;
		io_uring_cqe_seen(&ring, cqe);

		if (c->op == OP_ACCEPT) {
			if (res >= 0) {
				struct uconn *nc = calloc(1, sizeof(*nc));
				if (nc) { nc->fd = res; if (arm_recv(&ring, nc) < 0) { close(res); free(nc); } }
				else close(res);
			}
			free(c);                                    /* each accept SQE owns its state */
			if (res < 0 && res != -EINTR) usleep(10000);   /* e.g. EMFILE: don't spin re-arming */
			arm_accept(&ring, lfd);                     /* keep exactly one accept in flight */
		} else {                                        /* OP_RECV */
			if (res > 0 && r2dp_cp_dispatch(cp, c->fd, &c->msg, (size_t)res) == 0) {
				if (arm_recv(&ring, c) == 0) { io_uring_submit(&ring); continue; }
			}
			close(c->fd); free(c);                      /* EOF, error, or protocol violation: drop */
		}
		io_uring_submit(&ring);
	}
	io_uring_queue_exit(&ring);
	close(lfd);
	return 0;
}
#endif

int main(int argc, char **argv)
{
	static const struct option lo[] = { {"io", 1, 0, 'i'}, {"no-probe", 0, 0, 'n'}, {0, 0, 0, 0} };
	struct r2dp_cp_opts o = { .name = "kfwd" };
	struct r2dp_cp_caps caps;
	const char *path = NULL, *io = "poll";
	struct r2dp_cp *cp;
	int c, probe = 1, r;

	while ((c = getopt_long(argc, argv, "s:vK", lo, NULL)) != -1) {
		switch (c) {
		case 's': path = optarg; break;
		case 'v': o.verbose = 1; break;
		case 'K': o.echo_keys = 1; break;
		case 'i': io = optarg; break;
		case 'n': probe = 0; break;
		default: fprintf(stderr, "usage: %s [-s sock] [-v] [--io poll|uring] [--no-probe]\n", argv[0]); return 2;
		}
	}
	if (strcmp(io, "poll") && strcmp(io, "uring")) { fprintf(stderr, "kfwd: --io must be poll or uring\n"); return 2; }
#ifndef HAVE_LIBURING
	if (!strcmp(io, "uring")) { fprintf(stderr, "kfwd: built without liburing\n"); return 2; }
#endif
	signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGPIPE, SIG_IGN);

	if ((r = kx_open(o.verbose)) < 0) { fprintf(stderr, "kfwd: NETLINK_XFRM: %s (need root / CAP_NET_ADMIN)\n", strerror(-r)); return 1; }
	if (probe) {
		int n = kx_probe_caps(&caps);
		fprintf(stderr, "kfwd: kernel supports %d of the known transforms%s\n", n,
		        n ? "" : " (none: this kernel cannot install ESP states; SA requests will be refused)");
	} else kx_default_caps(&caps);

	if (!(cp = r2dp_cp_new(kx_hooks(), &caps, &o))) return 1;
	fprintf(stderr, "kfwd: ready (dataplane: kernel XFRM, control loop: %s)\n", io);

#ifdef HAVE_LIBURING
	if (!strcmp(io, "uring")) r = serve_uring(path, cp);
	else
#endif
	{
		struct r2dp_srv *srv = r2dp_srv_new(path);
		if (!srv) { perror("kfwd: listen"); return 1; }
		r = 0;
		while (!stop)
			if (r2dp_srv_poll(srv, cp, 500) < 0) break;
		r2dp_srv_free(srv);
	}
	r2dp_cp_free(cp); kx_close();
	return r;
}

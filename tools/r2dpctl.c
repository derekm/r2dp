/*
 * r2dpctl: minimal control client for the r2dp forwarder.
 *
 * Speaks the r2dp control protocol to a live r2dp-fwd over its unix
 * SOCK_SEQPACKET socket and prints the forwarder's view of its SAD (and
 * optionally SPD).  The exit gate requires "r2dpctl dump matches SAD": the
 * source of truth is the forwarder's in-process SAD, and this tool reads it
 * back over the wire via R2DP_SA_DUMP / R2DP_SP_DUMP.
 *
 * Usage:
 *   r2dpctl [socket] dump          # all SAs, one per line (keys withheld)
 *   r2dpctl [socket] dump-sa       # same as dump
 *   r2dpctl [socket] dump-sp       # all policies
 *   r2dpctl [socket] count         # number of live SAs (0 if empty; 255 if)
 *   r2dpctl [socket] get SPI DST   # single SA by key (spi hex, dst ipv4)
 *
 * socket defaults to $R2DP_SOCK else /var/run/r2dp.sock.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "r2dp/client.h"

static const char *g_sock = NULL;

static int
do_hello(int fd)
{
	struct r2dp_hello_ack ack;
	int r = r2dp_hello(fd, R2DP_ROLE_CTL, &ack);
	if (r < 0) {
		fprintf(stderr, "r2dpctl: hello: %s\n", strerror(-r));
		return -1;
	}
	return 0;
}

/* Send a dump request and print every reply until the last (MORE unset).
 * Return the number of entries, or a negative errno. */
static int
dump_loop(int fd, uint16_t type, int print)
{
	uint32_t seq = 0x444d5053;   /* 'DMPS' */
	int n = 0;
	int r = r2dp_send(fd, type, seq, 0, 0, NULL, 0, NULL, 0);
	if (r < 0)
		return r;

	for (;;) {
		struct r2dp_msg m;
		r = r2dp_recv(fd, &m);
		if (r < 0)
			return r;
		if (m.h.seq != seq || m.h.type != type)
			continue;   /* not our completion */
		if (m.h.status)      /* ENOENT => empty dump */
			return m.h.status == ENOENT ? 0 : -(int)m.h.status;
		n++;
		if (print) {
			if (type == R2DP_SA_DUMP) {
				const struct r2dp_sa *sa = r2dp_msg_sa(&m);
				char dst[64] = "?";
				if (sa->dst.family == R2DP_AF_INET4)
					inet_ntop(AF_INET, sa->dst.addr, dst, sizeof(dst));
				uint32_t spi = ntohl(sa->spi);
				printf("SA spi=0x%08x proto=%u mode=%u enc=%u "
				    "integ=%u dst=%s enckeylen=%u%s%s\n",
				    spi, sa->proto, sa->mode, sa->enc, sa->integ,
				    dst, sa->enckeylen,
				    (m.h.flags & R2DP_HF_MORE) ? " [more]" : "");
			} else {
				const struct r2dp_sp *sp = r2dp_msg_sp(&m);
				char s[64] = "?", d[64] = "?";
				if (sp->sel_src.family == R2DP_AF_INET4)
					inet_ntop(AF_INET, sp->sel_src.addr, s, sizeof(s));
				if (sp->sel_dst.family == R2DP_AF_INET4)
					inet_ntop(AF_INET, sp->sel_dst.addr, d, sizeof(d));
				printf("SP dir=%u action=%u slid=%u %s->%s proto=%u mode=%u\n",
				    sp->dir, sp->action, sp->slid, s, d,
				    sp->ul_proto, sp->mode);
			}
		}
		if (!(m.h.flags & R2DP_HF_MORE))
			return n;
	}
}

int
main(int argc, char **argv)
{
	const char *cmd = "dump";

	if (argc >= 2 && argv[1][0] == '-') {
		/* allow [socket] portability: unknown flags ignored */
		g_sock = getenv("R2DP_SOCK");
		cmd = "dump";
	} else if (argc >= 3) {
		g_sock = argv[1];
		cmd = argv[2];
	} else if (argc == 2) {
		cmd = argv[1];
	}

	if (!g_sock)
		g_sock = getenv("R2DP_SOCK");
	if (!g_sock)
		g_sock = "/var/run/r2dp.sock";

	int fd = r2dp_connect(g_sock);
	if (fd < 0) {
		fprintf(stderr, "r2dpctl: connect %s: %s\n",
		    g_sock, strerror(-fd));
		return 1;
	}
	if (do_hello(fd) < 0) {
		close(fd);
		return 1;
	}

	if (!strcmp(cmd, "dump") || !strcmp(cmd, "dump-sa")) {
		int n = dump_loop(fd, R2DP_SA_DUMP, 1);
		if (n < 0) { fprintf(stderr, "r2dpctl: SA dump: %s\n",
		    strerror(-n)); close(fd); return 1; }
		fprintf(stderr, "r2dpctl: %d SA(s)\n", n);
	} else if (!strcmp(cmd, "dump-sp")) {
		int n = dump_loop(fd, R2DP_SP_DUMP, 1);
		if (n < 0) { fprintf(stderr, "r2dpctl: SP dump: %s\n",
		    strerror(-n)); close(fd); return 1; }
		fprintf(stderr, "r2dpctl: %d SP(s)\n", n);
	} else if (!strcmp(cmd, "count")) {
		int n = dump_loop(fd, R2DP_SA_DUMP, 0);
		if (n < 0) { fprintf(stderr, "r2dpctl: count: %s\n",
		    strerror(-n)); close(fd); return 1; }
		printf("%d\n", n);
	} else {
		fprintf(stderr, "r2dpctl: unknown cmd '%s'\n", cmd);
		close(fd);
		return 2;
	}
	close(fd);
	return 0;
}

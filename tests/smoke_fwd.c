/*
 * smoke_fwd: drive a live r2dp-fwd control server over its unix socket
 * using libr2dp (the same library racoon2's shim links), independent of
 * mockfwd, to prove the forwarder's control plane serves the protocol.
 *
 * Spawns the r2dp-fwd binary (arg 1) on a temp socket, then drives it.
 * Usage: smoke_fwd <path-to-r2dp-fwd>
 */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "r2dp/client.h"

static int failures;
#define CHECK(cond, ...) do { if (!(cond)) { \
	fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); failures++; } } while (0)

static pid_t child = -1;
static char sockpath[128];

static int
spawn_fwd(const char *bin)
{
	pid_t p;

	snprintf(sockpath, sizeof(sockpath), "/tmp/r2dp-fwd-smoke-%ld.sock",
	    (long)getpid());
	unlink(sockpath);
	p = fork();
	if (p < 0)
		return -1;
	if (p == 0) {
		execl(bin, bin, "-s", sockpath, (char *)NULL);
		perror("execl r2dp-fwd");
		_exit(127);
	}
	child = p;
	return 0;
}

static void
wait_child(void)
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
rt(int fd, uint16_t type, const void *body, size_t blen,
    const void *tail, size_t tlen, struct r2dp_msg *reply)
{
	uint32_t seq = (uint32_t)type;
	int r;

	if ((r = r2dp_send(fd, type, seq, 0, 0, body, blen, tail, tlen)) < 0)
		return r;
	for (;;) {
		struct r2dp_msg m;
		r = r2dp_recv(fd, &m);
		if (r < 0) return r;
		if (m.h.seq == seq && m.h.type == type) {
			if (reply) *reply = m;
			return m.h.status ? -(int)m.h.status : 0;
		}
	}
}

int
main(int argc, char **argv)
{
	const char *bin = argc > 1 ? argv[1] : "r2dp-fwd";
	struct r2dp_hello_ack ack;
	struct r2dp_msg reply;
	struct r2dp_sa sa, gk;
	uint8_t blob[20];
	int fd, r, i;

	if (spawn_fwd(bin) < 0)
		return 2;
	for (i = 0; i < 200; i++) {
		fd = r2dp_connect(sockpath);
		if (fd >= 0) break;
		usleep(20000);
	}
	CHECK(fd >= 0, "connect %s: %s", sockpath, strerror(-fd));
	if (fd < 0) { wait_child(); return 1; }
	fprintf(stderr, "smoke: connected\n");

	r = r2dp_hello(fd, R2DP_ROLE_IKED, &ack);
	fprintf(stderr, "smoke: hello r=%d\n", r);
	CHECK(r == 0, "hello r=%d", r);
	CHECK(ack.max_msg == R2DP_MAX_MSG, "max_msg=%u", ack.max_msg);
	CHECK((ack.features & R2DP_FEAT_ESN) != 0, "features");

	memset(&sa, 0, sizeof(sa));
	sa.proto = R2DP_PROTO_ESP; sa.mode = R2DP_MODE_TUNNEL;
	sa.enc = R2DP_ENCR_AES_GCM_16; sa.integ = R2DP_INTEG_NONE;
	sa.spi_min = 0x4000; sa.spi_max = 0x4fff;
	sa.dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "10.0.0.2", sa.dst.addr);

	r = rt(fd, R2DP_GETSPI, &sa, sizeof(sa), NULL, 0, &reply);
	fprintf(stderr, "smoke: getspi r=%d\n", r);
	CHECK(r == 0, "getspi r=%d", r);
	{
		uint32_t spi = r2dp_msg_sa(&reply)->spi;
		CHECK(spi != 0, "getspi spi=0x%x", spi);

		sa.spi = spi;
		memset(blob, 0xAB, sizeof(blob));
		sa.enckeylen = sizeof(blob); sa.authkeylen = 0;
		r = rt(fd, R2DP_SA_ADD, &sa, sizeof(sa), blob, sizeof(blob), &reply);
		fprintf(stderr, "smoke: sa_add r=%d\n", r);
		CHECK(r == 0, "sa_add r=%d", r);
		CHECK((reply.h.flags & R2DP_HF_NOKEYS) != 0, "sa_add withholds keys");

		memset(&gk, 0, sizeof(gk));
		gk.proto = R2DP_PROTO_ESP; gk.spi = spi; gk.dst = sa.dst;
		r = rt(fd, R2DP_SA_GET, &gk, sizeof(gk), NULL, 0, &reply);
		fprintf(stderr, "smoke: sa_get r=%d\n", r);
		CHECK(r == 0, "sa_get r=%d", r);
		CHECK(r2dp_msg_sa(&reply)->spi == spi, "sa_get spi match");

		r = rt(fd, R2DP_SA_DEL, &gk, sizeof(gk), NULL, 0, &reply);
		CHECK(r == 0, "sa_del r=%d", r);
		r = rt(fd, R2DP_SA_DEL, &gk, sizeof(gk), NULL, 0, &reply);
		CHECK(r == -ENOENT, "sa_del again -> ENOENT got=%d", r);
	}

	close(fd);
	wait_child();
	if (failures) { fprintf(stderr, "smoke_fwd: %d failures\n", failures); return 1; }
	printf("smoke_fwd: OK (forwarder control plane serves protocol)\n");
	return 0;
}

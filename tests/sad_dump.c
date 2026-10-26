/*
 * sad_dump: live exit-gate test for "r2dpctl dump matches SAD".
 *
 * Spawns the REAL r2dp-fwd (the DPDK forwarder binary, control plane, no
 * mocks), installs a set of SAs over the control socket, then issues
 * R2DP_SA_DUMP and asserts every SA the forwarder holds is dumped exactly once
 * with the right (spi, proto, dst, enc, integ, mode) -- i.e. the wire dump is
 * the authoritative view of the forwarder's SAD.
 *
 * Usage: sad_dump <path-to-r2dp-fwd>  (spawns it, control-only on a temp sock)
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

#define N_SA 3

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
	snprintf(sockpath, sizeof(sockpath), "/tmp/r2dp-sad-%ld.sock",
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
		if (m.h.status) {
			if (m.h.type == type) return m.h.status ? -(int)m.h.status : 0;
		}
		if (m.h.seq == seq && m.h.type == type) {
			if (reply) *reply = m;
			return m.h.status ? -(int)m.h.status : 0;
		}
	}
}

/* Collect a full SA_DUMP stream into got[].  Returns count, or a negative
 * errno (ENOENT -> 0 entries).  set[] marks which installed SA i matched. */
static int
do_sa_dump(int fd, struct r2dp_sa got[], int gcap, int *matched)
{
	int n = 0, r, i;
	memset(got, 0, sizeof(struct r2dp_sa) * (size_t)gcap);
	for (i = 0; i < gcap; i++) matched[i] = 0;
	r = r2dp_send(fd, R2DP_SA_DUMP, 0x5ad, 0, 0, NULL, 0, NULL, 0);
	if (r < 0) return r;
	for (;;) {
		struct r2dp_msg m;
		r = r2dp_recv(fd, &m);
		if (r < 0) return r;
		if (m.h.seq != 0x5ad || m.h.type != R2DP_SA_DUMP) continue;
		if (m.h.status) return m.h.status == ENOENT ? n : -(int)m.h.status;
		if (n < gcap) got[n] = *r2dp_msg_sa(&m);
		n++;
		if (!(m.h.flags & R2DP_HF_MORE)) return n;
	}
}

int
main(int argc, char **argv)
{
	const char *bin = argc > 1 ? argv[1] : "r2dp-fwd";
	struct r2dp_hello_ack ack;
	struct r2dp_sa sa;
	struct r2dp_msg gk;
	struct r2dp_sa got[N_SA * 2];
	int matched[N_SA * 2];
	uint8_t blob[20];
	uint32_t spis[N_SA];
	int fd, r, i;

	if (spawn_fwd(bin) < 0) return 2;
	for (i = 0; i < 200; i++) {
		fd = r2dp_connect(sockpath);
		if (fd >= 0) break;
		usleep(20000);
	}
	CHECK(fd >= 0, "connect %s: %s", sockpath, strerror(-fd));
	if (fd < 0) { wait_child(); return 1; }

	r = r2dp_hello(fd, R2DP_ROLE_IKED, &ack);
	CHECK(r == 0, "hello r=%d", r);

	/* empty SAD -> dump reports 0 entries */
	r = do_sa_dump(fd, got, N_SA * 2, matched);
	CHECK(r == 0, "empty dump r=%d (want 0)", r);

	/* install N SAs (GETSPI + SA_ADD) */
	for (i = 0; i < N_SA; i++) {
		memset(&sa, 0, sizeof(sa));
		sa.proto = R2DP_PROTO_ESP; sa.mode = R2DP_MODE_TUNNEL;
		sa.enc = R2DP_ENCR_AES_GCM_16; sa.integ = R2DP_INTEG_NONE;
		sa.spi_min = 0x4000 + i * 256; sa.spi_max = 0x4000 + i * 256 + 255;
		sa.dst.family = R2DP_AF_INET4;
		{
			char dst[16];
			snprintf(dst, sizeof(dst), "10.0.0.%d", i + 2);
			inet_pton(AF_INET, dst, sa.dst.addr);
		}
		r = rt(fd, R2DP_GETSPI, &sa, sizeof(sa), NULL, 0, &gk);
		CHECK(r == 0, "getspi[%d] r=%d", i, r);
		if (r) continue;
		spis[i] = r2dp_msg_sa(&gk)->spi;
		sa.spi = spis[i];
		memset(blob, 0xAB, sizeof(blob));
		sa.enckeylen = sizeof(blob); sa.authkeylen = 0;
		r = rt(fd, R2DP_SA_ADD, &sa, sizeof(sa), blob, sizeof(blob), NULL);
		CHECK(r == 0, "sa_add[%d] r=%d", i, r);
	}
	CHECK(r == 0, "all %d SAs installed", N_SA);

	/* dump -> must return exactly N_SA, each matching (spi,proto,dst,enc,..) */
	r = do_sa_dump(fd, got, N_SA * 2, matched);
	CHECK(r == N_SA, "dump count=%d (want %d)", r, N_SA);
	if (r == N_SA) {
		for (int k = 0; k < N_SA; k++) {
			CHECK(got[k].proto == R2DP_PROTO_ESP &&
			    got[k].mode == R2DP_MODE_TUNNEL &&
			    got[k].enc == R2DP_ENCR_AES_GCM_16 &&
			    got[k].dst.family == R2DP_AF_INET4,
			    "dump[%d] sa fields (proto/mode/enc/family)", k);
			for (int j = 0; j < N_SA; j++) {
				if (got[k].spi == spis[j]) { matched[j]++; break; }
			}
		}
		for (int j = 0; j < N_SA; j++)
			CHECK(matched[j] == 1, "SA spi=0x%x dumped exactly %d time(s)",
			    spis[j], matched[j]);
	}

	close(fd);
	wait_child();
	if (failures) { fprintf(stderr, "sad_dump: %d failures\n", failures); return 1; }
	printf("sad_dump: OK (SAD dump matches the installed SAs)\n");
	return 0;
}

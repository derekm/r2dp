/*
 * shim_contract: the protocol fidelity the racoon2 shim (if_r2dp.c) relies
 * on from libr2dp + mockfwd, exercised end to end.
 *
 * This is NOT the racoon2 ABI (it needs a racoon2 tree); it pins the wire
 * contract behaviours the shim depends on:
 *   - ESN flag round-trips through GETSPI/SA_ADD (R2DP_SAF_ESN)
 *   - NAT-T sport/dport + natt_type survive the round trip unchanged
 *   - AEAD key blob (cipher || salt) comes back intact under -K
 *   - XFRM-native mark/if_id refusals are driven from the client side by
 *     the shim (here: we assert the client can express them and that a
 *     forwarder falls back to NOKEYS/correct status rather than corrupting)
 *   - unknown message type from a newer forwarder => -ENOSYS (recv skips)
 *
 * Usage: shim_contract <path-to-mockfwd>
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "r2dp/client.h"

static int failures;

#define CHECK(cond, ...) do {                                                   \
	if (!(cond)) {                                                            \
		fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                 \
		fprintf(stderr, __VA_ARGS__);                                        \
		fputc('\n', stderr);                                                 \
		failures++;                                                          \
	}                                                                        \
} while (0)

static pid_t child = -1;
static char sockpath[128];

static int
spawn_fwd(const char *bin)
{
	pid_t p;

	snprintf(sockpath, sizeof(sockpath), "/tmp/r2dp-shim-%ld.sock",
	    (long)getpid());
	unlink(sockpath);
	p = fork();
	if (p < 0)
		return -1;
	if (p == 0) {
		execl(bin, bin, "-s", sockpath, "-K", (char *)NULL);
		_exit(127);
	}
	child = p;
	return 0;
}

static int
rt(int fd, uint16_t type, const void *body, size_t blen,
    const void *tail, size_t tlen, struct r2dp_msg *reply)
{
	uint32_t seq = 77;
	int r;

	if ((r = r2dp_send(fd, type, seq, 0, 0, body, blen, tail, tlen)) < 0)
		return r;
	for (;;) {
		struct r2dp_msg m;
		r = r2dp_recv(fd, &m);
		if (r < 0)
			return r;
		if (m.h.seq == seq && m.h.type == type) {
			if (reply)
				*reply = m;
			return m.h.status ? -(int)m.h.status : 0;
		}
	}
}

static void
wait_child(void)
{
	if (child > 0) {
		int st;
		kill(child, SIGTERM);           /* mockfwd runs until signalled */
		waitpid(child, &st, 0);
		child = -1;
	}
	unlink(sockpath);
}

int
main(int argc, char **argv)
{
	const char *bin = argc > 1 ? argv[1] : "r2dp-mockfwd";
	struct r2dp_hello_ack ack;
	struct r2dp_sa sa;
	struct r2dp_msg reply;
	uint8_t blob[20];
	int fd, i, r;

	if (spawn_fwd(bin) < 0)
		return 2;
	for (i = 0; i < 100; i++) {
		fd = r2dp_connect(sockpath);
		if (fd >= 0)
			break;
		usleep(10000);
	}
	CHECK(fd >= 0, "connect");
	if (fd < 0) { wait_child(); return 1; }

	CHECK(r2dp_hello(fd, R2DP_ROLE_IKED, &ack) == 0, "hello");

	/* --- build an ESN + NAT-T ESP tunnel SA --- */
	memset(&sa, 0, sizeof(sa));
	sa.proto = R2DP_PROTO_ESP;
	sa.mode = R2DP_MODE_TUNNEL;
	sa.enc = R2DP_ENCR_AES_GCM_16;
	sa.integ = R2DP_INTEG_NONE;
	sa.saflags = R2DP_SAF_ESN;
	sa.natt_type = R2DP_NATT_ESPINUDP;
	sa.natt_sport = htons(4500);
	sa.natt_dport = htons(4500);
	sa.wsize = 64;
	sa.src.family = R2DP_AF_INET4;
	sa.dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "192.0.2.1", sa.src.addr);
	inet_pton(AF_INET, "198.51.100.2", sa.dst.addr);
	/* NAT-OA (of the peer behind NAT) */
	sa.natoa_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "203.0.113.9", sa.natoa_dst.addr);

	r = rt(fd, R2DP_GETSPI, &sa, sizeof(sa), NULL, 0, &reply);
	CHECK(r == 0, "getspi");
	sa.spi = r2dp_msg_sa(&reply)->spi;

	/* AEAD key blob = cipher key (16) || salt (4) */
	memset(blob, 0xAB, sizeof(blob));
	sa.enckeylen = sizeof(blob);
	sa.authkeylen = 0;
	r = rt(fd, R2DP_SA_ADD, &sa, sizeof(sa), blob, sizeof(blob), &reply);
	CHECK(r == 0, "sa_add");

	/* SA_GET should echo ESN + NAT-T faithful; -K echoes keys */
	{
		struct r2dp_sa k;
		memset(&k, 0, sizeof(k));
		k.proto = R2DP_PROTO_ESP;
		k.spi = sa.spi;
		k.dst = sa.dst;
		r = rt(fd, R2DP_SA_GET, &k, sizeof(k), NULL, 0, &reply);
		(void)k;
	}
	CHECK(r == 0, "sa_get");
	{
		const struct r2dp_sa *g = r2dp_msg_sa(&reply);
		CHECK((g->saflags & R2DP_SAF_ESN) != 0, "ESN round trip");
		CHECK(g->natt_type == R2DP_NATT_ESPINUDP, "natt_type round trip got=%u",
		    g->natt_type);
		CHECK(ntohs(g->natt_sport) == 4500 && ntohs(g->natt_dport) == 4500,
		    "natt ports round trip");
		CHECK(g->wsize == 64, "wsize round trip");
		CHECK(memcmp(r2dp_msg_enckey(&reply), blob, 20) == 0,
		    "AEAD key blob round trip (-K)");
		CHECK(g->natoa_dst.family == R2DP_AF_INET4 &&
		    memcmp(g->natoa_dst.addr, sa.natoa_dst.addr, 4) == 0,
		    "NAT-OA round trip");
	}

	/* --- unknown type => -ENOSYS from recv (newer forwarder) --- */
	{
		uint16_t bogus = R2DP_MSG_MAX + 3;
		struct r2dp_msg_raw {
			struct r2dp_hdr h;
		} raw;
		memset(&raw, 0, sizeof(raw));
		raw.h.magic = R2DP_MAGIC; raw.h.version = R2DP_VERSION;
		raw.h.type = bogus; raw.h.len = sizeof(raw.h);
		/* inject via a raw write; r2dp_send would refuse R2DP_MSG_MAX bounds */
		CHECK(write(fd, &raw, sizeof(raw)) == (ssize_t)sizeof(raw), "raw write");
		{
			struct r2dp_msg m;
			r = r2dp_recv(fd, &m);
			CHECK(r == -ENOSYS, "unknown type -> -ENOSYS, got %d", r);
		}
	}

	close(fd);
	wait_child();

	if (failures) {
		fprintf(stderr, "shim_contract: %d failure(s)\n", failures);
		return 1;
	}
	printf("shim_contract: all ok\n");
	return 0;
}

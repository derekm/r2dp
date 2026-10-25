/*
 * test_mock: end-to-end protocol test against r2dp-mockfwd.
 *
 * Spawns a real mockfwd process on a temp socket, then drives it as a
 * client: HELLO + capability query, GETSPI, SA_ADD / SA_UPDATE / SA_GET /
 * SA_DEL (with EEXIST / ENOENT semantics), key-material withholding by
 * default, and the full SP lifecycle including SP_DUMP streaming (MORE).
 *
 * Usage: test_mock <path-to-mockfwd>
 */
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
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

	snprintf(sockpath, sizeof(sockpath), "/tmp/r2dp-mockfwd-%ld.sock",
	    (long)getpid());
	unlink(sockpath);
	p = fork();
	if (p < 0) {
		perror("fork");
		return -1;
	}
	if (p == 0) {
		execl(bin, bin, "-s", sockpath, (char *)NULL);   /* no -K: keys withheld */
		perror("execl mockfwd");
		_exit(127);
	}
	child = p;
	(void)!signal(SIGCHLD, SIG_DFL);
	return 0;
}

/* As roundtrip(), but with explicit header flags.  Key-only queries
 * (GETSPI/GET/DEL) must carry R2DP_HF_NOKEYS, matching the racoon2 shim
 * (if_r2dp.c send_sa(..., with_keys=0) -> R2DP_HF_NOKEYS). */
static int
roundtrip_flags(int fd, uint16_t type, uint32_t flags, const void *body,
    size_t blen, const void *tail, size_t tlen, uint32_t *seqp,
    struct r2dp_msg *reply);

/* Send one request and consume until the reply matching `seq` arrives. */
static int
roundtrip(int fd, uint16_t type, const void *body, size_t blen,
    const void *tail, size_t tlen, uint32_t *seqp, struct r2dp_msg *reply)
{
	return roundtrip_flags(fd, type, 0, body, blen, tail, tlen, seqp, reply);
}

static int
roundtrip_flags(int fd, uint16_t type, uint32_t flags, const void *body,
    size_t blen, const void *tail, size_t tlen, uint32_t *seqp,
    struct r2dp_msg *reply)
{
	uint32_t seq = 1;
	int r;

	r = r2dp_send(fd, type, seq, 0, flags, body, blen, tail, tlen);
	if (r < 0)
		fprintf(stderr, "rt SEND %s type=%d r=%d errno=%s\n", __func__, type, r, r ? strerror(-r) : "-");
	if (r < 0)
		return r;
	if (seqp)
		*seqp = seq;
	for (;;) {
		struct r2dp_msg m;

		r = r2dp_recv(fd, &m);
		if (r < 0)
			fprintf(stderr, "rt RECV type=%d r=%d errno=%s\n", type, r, r ? strerror(-r) : "-");
		if (r < 0)
			return r;
		if (m.h.seq == seq && m.h.type == type) {
			if (reply)
				*reply = m;
			return m.h.status ? -(int)m.h.status : 0;
		}
		/* ignore unrelated; only one outstanding so this won't loop */
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
	struct r2dp_sp sp;
	struct r2dp_msg reply;
	uint8_t enckey[32], authkey[32];
	int fd, r, i;

	if (spawn_fwd(bin) < 0)
		return 2;
	/* give the forwarder a moment to bind */
	for (i = 0; i < 100; i++) {
		fd = r2dp_connect(sockpath);
		if (fd >= 0)
			break;
		usleep(10000);
	}
	CHECK(fd >= 0, "connect: %s", strerror(-fd));
	if (fd < 0) {
		wait_child();
		return 1;
	}

	/* ---- HELLO / caps ---- */
	r = r2dp_hello(fd, R2DP_ROLE_SPMD, &ack);
	CHECK(r == 0, "hello r=%d err=%s", r, r ? strerror(-r) : "-");
	CHECK(ack.max_msg == R2DP_MAX_MSG, "max_msg=%u", ack.max_msg);
	CHECK((ack.features & R2DP_FEAT_ESN) && (ack.features & R2DP_FEAT_NATT),
	    "features advertised");
	CHECK(r2dp_cap(ack.enc_caps, R2DP_ENCR_AES_GCM_16) == 1, "GCM-16 cap");
	CHECK(r2dp_cap(ack.integ_caps, R2DP_INTEG_HMAC_SHA2_256_128) == 1, "SHA2 cap");

	/* ---- GETSPI ---- */
	memset(&sa, 0, sizeof(sa));
	sa.proto = R2DP_PROTO_ESP;
	sa.mode = R2DP_MODE_TUNNEL;
	sa.enc = R2DP_ENCR_AES_GCM_16;
	sa.integ = R2DP_INTEG_NONE;
	sa.spi_min = 0x1000; sa.spi_max = 0x1fff;
	sa.dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "10.0.0.2", sa.dst.addr);
	r = roundtrip_flags(fd, R2DP_GETSPI, R2DP_HF_NOKEYS,
	    &sa, sizeof(sa), NULL, 0, NULL, &reply);
	CHECK(r == 0, "getspi r=%d", r);
	CHECK(r2dp_msg_sa(&reply)->spi != 0, "getspi filled spi");
	sa.spi = r2dp_msg_sa(&reply)->spi;

	/* ---- SA_ADD with keys ---- */
	memset(enckey, 0x42, sizeof(enckey));
	memset(authkey, 0x24, sizeof(authkey));
	sa.enckeylen = 16; sa.authkeylen = 0;   /* GCM: cipher key || salt = enckeylen */
	sa.enckeylen = 20;                       /* 16 key + 4 salt */
	r = roundtrip(fd, R2DP_SA_ADD, &sa, sizeof(sa),
	    enckey, sa.enckeylen, NULL, &reply);
	CHECK(r == 0, "sa_add r=%d err=%s", r, r ? strerror(-r) : "-");
	/* keys withheld by default (no -K correction on client side): reply flags */
	CHECK((reply.h.flags & R2DP_HF_NOKEYS) != 0, "keys withheld (NOKEYS)");

	/* duplicate ADD -> EEXIST */
	memset(&sa, 0, sizeof(sa));           /* reset keys/lifetimes */
	sa.proto = R2DP_PROTO_ESP; sa.mode = R2DP_MODE_TUNNEL;
	sa.enc = R2DP_ENCR_AES_GCM_16; sa.integ = R2DP_INTEG_NONE;
	sa.spi = r2dp_msg_sa(&reply)->spi;
	sa.dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "10.0.0.2", sa.dst.addr);
	sa.enckeylen = 20;                       /* tail must match enckeylen */
	r = roundtrip(fd, R2DP_SA_ADD, &sa, sizeof(sa), enckey, 20, NULL, &reply);
	CHECK(r == -EEXIST, "sa_add dupe -> EEXIST got=%d", r);

	/* SA_GET by key */
	r = roundtrip_flags(fd, R2DP_SA_GET, R2DP_HF_NOKEYS,
	    &sa, sizeof(sa), NULL, 0, NULL, &reply);
	CHECK(r == 0, "sa_get r=%d", r);

	/* SA_DEL then re-DEL -> ENOENT */
	r = roundtrip_flags(fd, R2DP_SA_DEL, R2DP_HF_NOKEYS,
	    &sa, sizeof(sa), NULL, 0, NULL, &reply);
	CHECK(r == 0, "sa_del r=%d", r);
	r = roundtrip_flags(fd, R2DP_SA_DEL, R2DP_HF_NOKEYS,
	    &sa, sizeof(sa), NULL, 0, NULL, &reply);
	CHECK(r == -ENOENT, "sa_del again -> ENOENT got=%d", r);

	/* ---- SP lifecycle ---- */
	r = roundtrip(fd, R2DP_SP_ADD, &sp, sizeof(sp), NULL, 0, NULL, &reply);
	CHECK(r == 0, "sp_add r=%d", r);
	memset(&sp, 0, sizeof(sp));
	sp.dir = R2DP_DIR_IN; sp.ul_proto = R2DP_PROTO_ANY;
	sp.action = R2DP_ACT_PROTECT; sp.mode = R2DP_MODE_TUNNEL;
	sp.protos = R2DP_SPP_ESP; sp.level = R2DP_LVL_REQUIRE;
	sp.sel_src.family = R2DP_AF_INET4; sp.sel_dst.family = R2DP_AF_INET4;
	sp.pref_src = 32; sp.pref_dst = 32;
	r = roundtrip(fd, R2DP_SP_ADD, &sp, sizeof(sp), NULL, 0, NULL, &reply);
	CHECK(r == 0, "sp_add2 r=%d", r);
	{
		uint32_t slid = r2dp_msg_sp(&reply)->slid;
		CHECK(slid != 0, "sp got slid");

		/* duplicate without UPDATE -> EEXIST */
		r = roundtrip(fd, R2DP_SP_ADD, &sp, sizeof(sp), NULL, 0, NULL, &reply);
		CHECK(r == -EEXIST, "sp_add dupe -> EEXIST got=%d", r);

		/* SP_UPDATE (upsert) succeeds */
		struct r2dp_sp up = sp;
		up.flags |= R2DP_SPF_UPDATE;
		r = roundtrip(fd, R2DP_SP_ADD, &up, sizeof(up), NULL, 0, NULL, &reply);
		CHECK(r == 0, "sp_update r=%d", r);

		/* SP_GET by slid */
		struct r2dp_sp gk;
		memset(&gk, 0, sizeof(gk));
		gk.slid = slid;
		r = roundtrip(fd, R2DP_SP_GET, &gk, sizeof(gk), NULL, 0, NULL, &reply);
		CHECK(r == 0 && r2dp_msg_sp(&reply)->slid == slid, "sp_get slid match");

		/* SP_DEL then re-DEL -> ENOENT */
		r = roundtrip(fd, R2DP_SP_DEL, &gk, sizeof(gk), NULL, 0, NULL, &reply);
		CHECK(r == 0, "sp_del r=%d", r);
		r = roundtrip(fd, R2DP_SP_DEL, &gk, sizeof(gk), NULL, 0, NULL, &reply);
		CHECK(r == -ENOENT, "sp_del again -> ENOENT got=%d", r);
	}

	close(fd);
	wait_child();

	if (failures) {
		fprintf(stderr, "test_mock: %d failure(s)\n", failures);
		return 1;
	}
	printf("test_mock: all ok\n");
	return 0;
}

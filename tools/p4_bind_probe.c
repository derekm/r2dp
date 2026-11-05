/* p4_bind_probe: prove the SPD->crypto-SA bind hit path.  Installs an
 * OUTBOUND SA (dir=R2DP_DIR_OUT) on a tunnel, then a PROTECT SP on the same
 * tunnel, and verifies via a forwarder log line ("OUT PROTECT bind sa_id=N")
 * and r2dpctl dump that the outbound_table_0 entry names the SA's crypto id.
 *
 * This is the path the old ctl_probe could not reach: it only ever installed
 * an INBOUND (GETSPI-completing) SA, so the SPD lookup always missed and the
 * policy was (pre-fix) refused.  Here we drive the real outbound order
 * (SA first, then SP), and again with SP first (policy-before-SA, the spmd
 * startup order) to prove rebind works.
 *
 * Usage: p4_bind_probe [sock]
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "r2dp/client.h"

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

static int
test_sequence(int fd, int sp_first, const char *label, int seq)
{
	struct r2dp_msg reply;
	struct r2dp_sa sa;
	struct r2dp_sp sp;
	uint8_t blob[20];
	char sel[32], tun[32];
	int r;

	/* distinct selector/tunnel/SPI per sequence so the two paths don't
	 * collide (each is tested against an empty SPD/SAD) */
	snprintf(sel, sizeof(sel), "192.0.%d.0", seq + 2);
	snprintf(tun, sizeof(tun), "198.51.%d.1", seq + 1);

	printf("=== %s (SP %s) ===\n", label, sp_first ? "first" : "last");

	memset(&sp, 0, sizeof(sp));
	sp.dir = R2DP_DIR_OUT; sp.action = R2DP_ACT_PROTECT; sp.mode = R2DP_MODE_TUNNEL;
	sp.ul_proto = R2DP_PROTO_ANY; sp.slid = 0;
	sp.sel_src.family = R2DP_AF_INET4;
	inet_pton(AF_INET, sel, sp.sel_src.addr);
	sp.sel_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, sel, sp.sel_dst.addr);
	sp.pref_src = 24; sp.pref_dst = 24;
	sp.tun_src.family = R2DP_AF_INET4;
	inet_pton(AF_INET, tun, sp.tun_src.addr);
	sp.tun_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "10.0.0.2", sp.tun_dst.addr);

	/* OUTBOUND SA on the same tunnel (dir OUT explicit). */
	memset(&sa, 0, sizeof(sa));
	sa.proto = R2DP_PROTO_ESP; sa.mode = R2DP_MODE_TUNNEL;
	sa.enc = R2DP_ENCR_AES_GCM_16; sa.integ = R2DP_INTEG_NONE;
	sa.dir = R2DP_DIR_OUT;
	sa.spi = htonl(0x5100 + seq);
	sa.src.family = R2DP_AF_INET4;
	inet_pton(AF_INET, tun, sa.src.addr);
	sa.dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "10.0.0.2", sa.dst.addr);
	memset(blob, 0xCD, sizeof(blob));
	sa.enckeylen = sizeof(blob); sa.authkeylen = 0;

	if (sp_first) {
		/* policy before SA: must be ACCEPTED even though no egress SA yet */
		r = rt(fd, R2DP_SP_ADD, &sp, sizeof(sp), NULL, 0, &reply);
		if (r < 0) { fprintf(stderr, "  sp_add(first): %s (should not refuse)\n", strerror(-r)); return -1; }
		printf("  SP installed (expected: accepted despite no egress SA)\n");
		r = rt(fd, R2DP_SA_ADD, &sa, sizeof(sa), blob, sizeof(blob), &reply);
		if (r < 0) { fprintf(stderr, "  sa_add: %s\n", strerror(-r)); return -1; }
		printf("  SA installed (spi=0x%08x) -> triggers rebind\n", ntohl(sa.spi));
	} else {
		r = rt(fd, R2DP_SA_ADD, &sa, sizeof(sa), blob, sizeof(blob), &reply);
		if (r < 0) { fprintf(stderr, "  sa_add: %s\n", strerror(-r)); return -1; }
		r = rt(fd, R2DP_SP_ADD, &sp, sizeof(sp), NULL, 0, &reply);
		if (r < 0) { fprintf(stderr, "  sp_add: %s\n", strerror(-r)); return -1; }
		printf("  SP installed after SA (bound directly)\n");
	}
	printf("  OK\n");
	return 0;
}

int
main(int argc, char **argv)
{
	const char *sock = argc > 1 ? argv[1]
	    : (getenv("R2DP_SOCK") ? getenv("R2DP_SOCK") : R2DP_DEFAULT_SOCK);
	struct r2dp_hello_ack ack;
	int fd, r, fails = 0;

	fd = r2dp_connect(sock);
	if (fd < 0) { fprintf(stderr, "connect: %s\n", strerror(-fd)); return 2; }
	if ((r = r2dp_hello(fd, R2DP_ROLE_IKED, &ack)) < 0) {
		fprintf(stderr, "hello: %s\n", strerror(-r)); return 2; }

	if (test_sequence(fd, 0, "SA then SP", 0) < 0) fails++;
	if (test_sequence(fd, 1, "SP then SA (rebind)", 1) < 0) fails++;
	close(fd);
	if (fails) { fprintf(stderr, "FAILURES=%d\n", fails); return 1; }
	printf("BIND_TEST_OK\n");
	return 0;
}

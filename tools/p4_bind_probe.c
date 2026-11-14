/* p4_bind_probe: prove the SPD->crypto-SA bind path AND that unbound OUT
 * PROTECT is FAIL-CLOSED.  Installs an OUTBOUND SA (dir=R2DP_DIR_OUT) on a
 * tunnel and a PROTECT SP on the same tunnel, in both orders, and asserts
 * the forwarder log shows the dataplane action:
 *   - SA-then-SP: direct bind ("OUT PROTECT bind sa_id=N"), NO discard.
 *   - SP-then-SA: unbound SP programs to spd_discard ("OUT PROTECT unbound
 *     -> DISCARD"), then the SA triggers a rebind to ipsec_protect.
 *
 * This is the path the old ctl_probe could not reach: it only ever installed
 * an INBOUND (GETSPI-completing) SA, so the SPD lookup always missed.  Here
 * we drive the real OUTBOUND order (SA first, then SP) and the spmd startup
 * order (SP first) to prove rebind AND fail-closed.
 *
 * Honest scope: this proves the TABLE INSTALL action from the log, NOT that a
 * real packet hits spd_discard.  It installs R2DP_PROTO_ANY and /24 selectors
 * (like spmd) — the SPD table is now a WILDCARD (ternary) table (`a8aedd2`) so
 * these install as SEPARATE prefix/ANY wildcard rows that match their selectors
 * (they do NOT collapse into one entry — that collapse was Limit 4's bug);
 * still assert spd_discard
 * on a hit and never claim packet-hit or DR_NO_SA_OUT parity without a wire
 * proof.  This probe checks the bind log only.
 *
 * Usage: p4_bind_probe [sock] [fwd-log-path]
 *   fwd-log-path (optional) enables the log-action assertions; without it
 *   only the control-plane return codes are checked, which do NOT prove the
 *   table action (r2dpctl dump only echoes the client SA, not the SPD
 *   table entry).
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
test_sequence(int fd, int sp_first, const char *label, int seq,
	      const char *log, unsigned *log_pos)
{
	struct r2dp_msg reply;
	struct r2dp_sa sa;
	struct r2dp_sp sp;
	uint8_t blob[20];
	char sel[32], tun[32];
	FILE *lf;
	char line[256];
	int r, saw_discard = 0, saw_bind = 0;
	unsigned pos = *log_pos;

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
		/* policy before SA: must be ACCEPTED and programmed to
		 * DISCARD (fail-closed), NOT bypass. */
		r = rt(fd, R2DP_SP_ADD, &sp, sizeof(sp), NULL, 0, &reply);
		if (r < 0) { fprintf(stderr, "  sp_add(first): %s (should not refuse)\n", strerror(-r)); return -1; }
		printf("  SP installed (expected: accepted, FAIL-CLOSED to discard)\n");
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

	/* With a forwarder log path, assert the dataplane action: SP-first must
	 * log an unbound DISCARD then a bind; SA-first must bind directly with
	 * NO discard.  Return codes alone do not prove the table action. */
	if (!log)
		goto done;
	usleep(200 * 1000);   /* let the worker/flush -- the log lines are
				 emitted synchronously in sa_add/sp_add, but
				 allow for the ring round-trip */
	lf = fopen(log, "r");
	if (!lf) { fprintf(stderr, "  cannot open fwd log %s\n", log); return -1; }
	fseek(lf, (long)pos, SEEK_SET);
	while (fgets(line, sizeof(line), lf)) {
		pos = (unsigned)ftell(lf);
		if (strstr(line, "OUT PROTECT unbound -> DISCARD"))
			saw_discard = 1;
		if (strstr(line, "OUT PROTECT bind sa_id="))
			saw_bind++;
	}
	fclose(lf);
	*log_pos = pos;
	if (sp_first && (!saw_discard || !saw_bind)) {
		fprintf(stderr, "  FAIL: SP-first expected discard THEN bind "
			"(discard=%d bind=%d)\n", saw_discard, saw_bind);
		return -1;
	}
	if (!sp_first && (!saw_bind || saw_discard)) {
		fprintf(stderr, "  FAIL: SA-first expected bind, no discard "
			"(discard=%d bind=%d)\n", saw_discard, saw_bind);
		return -1;
	}
	printf("  log confirms %s (discard=%d bind=%d)\n",
	       sp_first ? "discard-then-bind" : "direct bind, no discard",
	       saw_discard, saw_bind);
done:
	printf("  OK\n");
	return 0;
}

int
main(int argc, char **argv)
{
	const char *sock = argc > 1 ? argv[1]
	    : (getenv("R2DP_SOCK") ? getenv("R2DP_SOCK") : R2DP_DEFAULT_SOCK);
	const char *log = argc > 2 ? argv[2] : NULL;
	struct r2dp_hello_ack ack;
	unsigned pos = 0;
	int fd, r, fails = 0;

	fd = r2dp_connect(sock);
	if (fd < 0) { fprintf(stderr, "connect: %s\n", strerror(-fd)); return 2; }
	if ((r = r2dp_hello(fd, R2DP_ROLE_IKED, &ack)) < 0) {
		fprintf(stderr, "hello: %s\n", strerror(-r)); return 2; }

	if (test_sequence(fd, 0, "SA then SP", 0, log, &pos) < 0) fails++;
	if (test_sequence(fd, 1, "SP then SA (rebind)", 1, log, &pos) < 0) fails++;
	close(fd);
	if (fails) { fprintf(stderr, "FAILURES=%d\n", fails); return 1; }
	printf("BIND_TEST_OK\n");
	return 0;
}

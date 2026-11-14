/* p4_map: the ctl -> SWX extern parameter mapping (COMMITS C6, P4 P2). */
#include <stdio.h>
#include "../fwd/p4_map.h"

static int fails;
#define CHECK(c, msg) do { if (c) printf("ok   %s\n", msg); \
	else { printf("FAIL %s\n", msg); fails++; } } while (0)

/* Fake regarray writer: records writes, fails the fail_at-th one. */
static unsigned nwr, fail_at;
static int fake_rc;
static int
fake_wr(void *ctx, const char *name, uint32_t idx, uint64_t val)
{
	(void)ctx; (void)name; (void)idx; (void)val;
	return nwr++ == fail_at ? fake_rc : 0;
}

int
main(void)
{
	static const struct { uint32_t w; int rc; uint32_t W; } t[] = {
		{ 0, 0, 0 }, { 1, -EOPNOTSUPP, 0 }, { 2, 0, 1 }, { 32, 0, 31 },
		{ 63, 0, 62 }, { 64, 0, 63 }, { 65, 0, 64 }, { 1024, 0, 1023 },
	};
	uint32_t W;
	int ok = 1;

	for (unsigned i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		int rc = p4_replay_win(t[i].w, 1, &W);
		if (rc != t[i].rc || W != t[i].W) {
			printf("     w=%u: rc=%d W=%u\n", t[i].w, rc, W);
			ok = 0;
		}
	}
	CHECK(ok, "window w maps to inclusive W = w-1; w=1 refused, never 'off'");
	CHECK(p4_replay_win(64, 0, &W) == -EOPNOTSUPP && W == 0,
	    "stock extern: a requested window is refused");
	CHECK(p4_replay_win(0, 0, &W) == 0 && W == 0,
	    "stock extern: anti-replay off is representable");
	CHECK(p4_sa_supported(1, 64, 1, 0, 1, 1, &W) == -EOPNOTSUPP,
	    "ESN SA refused");
	CHECK(p4_sa_supported(0, 0, 0, 1, 1, 0, &W) == -EOPNOTSUPP,
	    "NAT-T SA refused without the NAT-T extern");
	CHECK(p4_sa_supported(0, 64, 0, 1, 0, 1, &W) == 0 && W == 0,
	    "outbound SA ignores the receive window");
	CHECK(p4_sa_supported(1, 64, 0, 0, 1, 1, &W) == 0 && W == 63,
	    "inbound SA with window 64 -> W 63");
	CHECK(p4_sp_supported(0, 0) == 0, "address/protocol-only selector accepted");
	CHECK(p4_sp_supported(0, 500) == -EOPNOTSUPP &&
	    p4_sp_supported(4500, 0) == -EOPNOTSUPP,
	    "port-qualified selector refused, never widened to all ports");
	CHECK(p4_sa_outranks(0, 0, 2, 0, 1) && !p4_sa_outranks(0, 0, 1, 0, 2),
	    "reqid 0: newest endpoint match wins (rekey overlap)");
	CHECK(p4_sa_outranks(7, 7, 1, 9, 2) && !p4_sa_outranks(7, 9, 2, 7, 1),
	    "matching nonzero reqid outranks a newer SA with another reqid");
	CHECK(p4_sa_outranks(7, 7, 3, 7, 2) && !p4_sa_outranks(7, 7, 2, 7, 3),
	    "newest wins among reqid matches");
	CHECK(p4_sa_outranks(7, 0, 2, 9, 1),
	    "no reqid match: newest endpoint match, as on main");
	CHECK(p4_lft_supported(0, 0) == 0, "infinite byte lifetime accepted");
	CHECK(p4_lft_supported(1 << 20, 0) == -EOPNOTSUPP &&
	    p4_lft_supported(0, 1 << 20) == -EOPNOTSUPP,
	    "finite hard/soft byte lifetime refused, never left unenforced");
	nwr = 0; fail_at = ~0u;
	{
		unsigned bad = 99;
		CHECK(p4_regs_program(fake_wr, NULL, &bad) == 0 && nwr == P4_NREGS,
		    "every classification regarray is written");
		ok = 1;
		for (unsigned i = 0; i < P4_NREGS; i++) {
			int want = i & 1 ? -EINVAL : -EIO;
			nwr = 0; fail_at = i; fake_rc = i & 1 ? -EINVAL : 1;
			bad = 99;
			if (p4_regs_program(fake_wr, NULL, &bad) != want ||
			    bad != i || nwr != i + 1)
				ok = 0;
		}
		CHECK(ok, "a failed regarray write stops setup and names the entry");
	}
	if (fails) { printf("p4_map: %d failures\n", fails); return 1; }
	puts("p4_map: OK");
	return 0;
}

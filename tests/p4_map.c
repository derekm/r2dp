/* p4_map: the ctl -> SWX extern parameter mapping (COMMITS C6, P4 P2). */
#include <stdio.h>
#include "../fwd/p4_map.h"

static int fails;
#define CHECK(c, msg) do { if (c) printf("ok   %s\n", msg); \
	else { printf("FAIL %s\n", msg); fails++; } } while (0)

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
	if (fails) { printf("p4_map: %d failures\n", fails); return 1; }
	puts("p4_map: OK");
	return 0;
}

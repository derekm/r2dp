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

/* Ethernet + IPv4 frame: ihl words, proto, frag field, then a UDP
 * header (sport, dport) after the options. */
static size_t
mkframe(uint8_t *f, unsigned ihl, uint8_t proto, uint16_t frag,
    uint16_t sport, uint16_t dport)
{
	size_t hl = ihl * 4u;
	memset(f, 0, 128);
	f[12] = 0x08; f[13] = 0x00;
	f[14] = (uint8_t)(0x40 | ihl);
	f[14 + 6] = (uint8_t)(frag >> 8); f[14 + 7] = (uint8_t)frag;
	f[14 + 9] = proto;
	f[14 + 12] = 203; f[14 + 13] = 0; f[14 + 14] = 113; f[14 + 15] = 1;
	f[14 + 16] = 192; f[14 + 17] = 0; f[14 + 18] = 2;  f[14 + 19] = 1;
	for (size_t i = 20; i < hl; i++)
		f[14 + i] = 0x01;            /* NOP options */
	f[14 + hl] = (uint8_t)(sport >> 8); f[14 + hl + 1] = (uint8_t)sport;
	f[14 + hl + 2] = (uint8_t)(dport >> 8); f[14 + hl + 3] = (uint8_t)dport;
	f[14 + hl + 8] = 0x12; f[14 + hl + 9] = 0x34;   /* SPI-ish bytes */
	return 14 + hl + 8 + 64;
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
	{
		uint8_t f[128];
		int same = 1, ihl_ok = 1, spread = 0;
		for (uint32_t n = 2; n <= 8; n++) {
			size_t l = mkframe(f, 5, 17, 0, 4500, 4500);
			uint32_t whole = p4_flow_slice_of(f, l, n);
			l = mkframe(f, 5, 17, 0x2000, 4500, 4500);      /* first frag */
			same &= p4_flow_slice_of(f, l, n) == whole;
			l = mkframe(f, 5, 17, 0x0010, 0, 0);            /* later frag */
			same &= p4_flow_slice_of(f, l, n) == whole;
			l = mkframe(f, 5, 17, 0x2010, 0, 0);            /* middle */
			same &= p4_flow_slice_of(f, l, n) == whole;
			l = mkframe(f, 5, 50, 0, 0, 0);                 /* ESP */
			same &= p4_flow_slice_of(f, l, n) == whole;
			l = mkframe(f, 7, 17, 0, 4500, 4500);           /* IHL 7 */
			ihl_ok &= p4_flow_slice_of(f, l, n) == whole;
		}
		CHECK(same, "one NAT-T SA: whole, first, middle and last fragments "
		    "and ESP share a slice (N=2..8)");
		CHECK(ihl_ok, "NAT-T behind IPv4 options steers like IHL 5");
		{
			uint8_t bb[16];
			size_t l = mkframe(f, 6, 6, 0, 1234, 80);
			CHECK(p4_flow_key(f, l, bb) == 13 && bb[9] == 0x04 &&
			    bb[10] == 0xd2 && bb[11] == 0 && bb[12] == 80,
			    "5-tuple ports read after the real IHL");
			l = mkframe(f, 3, 17, 0, 4500, 4500);         /* bad IHL */
			CHECK(p4_flow_key(f, l, bb) == 9,
			    "malformed IHL hashes as raw IP, never reads ports");
			f[12] = 0x86; f[13] = 0xdd;
			CHECK(p4_flow_key(f, l, bb) == 0, "non-IPv4 hashes the frame");
		}
		for (uint16_t sp = 1000; sp < 1064; sp++) {
			size_t l = mkframe(f, 5, 17, 0, sp, 53);
			spread |= 1u << p4_flow_slice_of(f, l, 4);
		}
		CHECK(spread == 0xf, "unfragmented UDP flows still spread over slices");
	}
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

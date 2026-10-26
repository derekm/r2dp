/*
 * sel_test: selector matching (fwd/dp_sel.c), review finding M5: port
 * selectors are honoured (never silently skipped), prefixes are exact.
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "dp_sel.h"

static int fails;
#define CHECK(c, m) do { if (c) printf("ok   %s\n", m); \
	else { printf("FAIL %s\n", m); fails++; } } while (0)

static size_t
pkt(uint8_t *p, const char *src, const char *dst, uint8_t proto,
    uint16_t sport, uint16_t dport, uint16_t frag)
{
	memset(p, 0, 64);
	p[0] = 0x45; p[9] = proto;
	p[6] = (uint8_t)(frag >> 8); p[7] = (uint8_t)frag;
	inet_pton(AF_INET, src, p + 12);
	inet_pton(AF_INET, dst, p + 16);
	p[20] = (uint8_t)(sport >> 8); p[21] = (uint8_t)sport;
	p[22] = (uint8_t)(dport >> 8); p[23] = (uint8_t)dport;
	return 40;
}

static void
sp_init(struct r2dp_sp *sp, const char *s, uint8_t ps, const char *d, uint8_t pd)
{
	memset(sp, 0, sizeof(*sp));
	sp->ul_proto = R2DP_PROTO_ANY;
	sp->sel_src.family = sp->sel_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, s, sp->sel_src.addr);
	inet_pton(AF_INET, d, sp->sel_dst.addr);
	sp->pref_src = ps; sp->pref_dst = pd;
}

int
main(void)
{
	struct r2dp_sp sp, wide;
	uint8_t p[64];
	size_t n;

	sp_init(&sp, "10.1.0.0", 16, "10.2.0.0", 16);
	n = pkt(p, "10.1.3.4", "10.2.9.9", 1, 0, 0, 0);
	CHECK(r2dp_sel_match(&sp, p, n), "/16 -> /16 match");
	n = pkt(p, "10.3.3.4", "10.2.9.9", 1, 0, 0, 0);
	CHECK(!r2dp_sel_match(&sp, p, n), "src outside prefix");
	sp_init(&sp, "10.1.0.128", 25, "0.0.0.0", 0);
	n = pkt(p, "10.1.0.200", "8.8.8.8", 1, 0, 0, 0);
	CHECK(r2dp_sel_match(&sp, p, n), "/25 partial byte match");
	n = pkt(p, "10.1.0.100", "8.8.8.8", 1, 0, 0, 0);
	CHECK(!r2dp_sel_match(&sp, p, n), "/25 partial byte mismatch");
	sp.pref_src = 40;
	CHECK(!r2dp_sel_match(&sp, p, n), "invalid prefix never matches");

	/* ports (network order in r2dp_addr.port) */
	sp_init(&sp, "10.1.0.0", 16, "10.2.0.0", 16);
	sp.ul_proto = 6; sp.sel_dst.port = htons(443);
	n = pkt(p, "10.1.0.1", "10.2.0.1", 6, 50000, 443, 0);
	CHECK(r2dp_sel_match(&sp, p, n), "TCP dst port 443 matches");
	n = pkt(p, "10.1.0.1", "10.2.0.1", 6, 50000, 80, 0);
	CHECK(!r2dp_sel_match(&sp, p, n), "TCP dst port 80 does not");
	n = pkt(p, "10.1.0.1", "10.2.0.1", 17, 50000, 443, 0);
	CHECK(!r2dp_sel_match(&sp, p, n), "ul_proto TCP excludes UDP");
	sp.ul_proto = R2DP_PROTO_ANY;
	n = pkt(p, "10.1.0.1", "10.2.0.1", 1, 0, 0, 0);
	CHECK(!r2dp_sel_match(&sp, p, n), "port selector never matches ICMP");
	n = pkt(p, "10.1.0.1", "10.2.0.1", 6, 50000, 443, 0x0010);
	CHECK(!r2dp_sel_match(&sp, p, n), "port selector never matches non-first fragment");
	n = pkt(p, "10.1.0.1", "10.2.0.1", 6, 50000, 443, 0);
	CHECK(!r2dp_sel_match(&sp, p, 22), "truncated L4 header does not match");
	sp.sel_src.port = htons(50000);
	CHECK(r2dp_sel_match(&sp, p, n), "src+dst ports match");

	/* a port-specific policy outranks the covering wide one */
	sp_init(&wide, "10.1.0.0", 16, "10.2.0.0", 16);
	CHECK(r2dp_sel_score(&sp) > r2dp_sel_score(&wide),
	    "port-specific policy is more specific than the wide one");
	CHECK(r2dp_sel_match(&wide, p, n), "wide policy also matches");

	if (fails) { printf("sel_test: %d failures\n", fails); return 1; }
	puts("sel_test: OK");
	return 0;
}

/*
 * nh_test: unit tests for the next-hop learning classifier (fwd/dp_nh.c),
 * N1: learn only from unicast IPv4 IKE (UDP 500/4500) or ESP.  The table
 * itself (fwd/dpdk_nh.c) is covered by nh_tab.
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "dp_nh.h"

static int fails;
#define CHECK(c, m) do { if (c) printf("ok   %s\n", m); \
	else { printf("FAIL %s\n", m); fails++; } } while (0)

static size_t
frame(uint8_t *f, const uint8_t dmac[6], const uint8_t smac[6],
    const char *sip, uint8_t proto, uint16_t sport, uint16_t dport)
{
	memset(f, 0, 64);
	memcpy(f, dmac, 6); memcpy(f + 6, smac, 6);
	f[12] = 0x08; f[13] = 0x00;
	f[14] = 0x45; f[14 + 9] = proto;
	inet_pton(AF_INET, sip, f + 14 + 12);
	inet_pton(AF_INET, "192.0.2.1", f + 14 + 16);
	f[34] = (uint8_t)(sport >> 8); f[35] = (uint8_t)sport;
	f[36] = (uint8_t)(dport >> 8); f[37] = (uint8_t)dport;
	return 64;
}

int
main(void)
{
	const uint8_t us[6] = { 0x02, 0, 0, 0, 0, 1 };
	const uint8_t peer[6] = { 0x02, 0, 0, 0, 0, 2 };
	const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	uint8_t f[64];
	uint32_t ip, pip;
	const uint8_t *m;
	size_t n;

	inet_pton(AF_INET, "192.0.2.2", &pip);

	n = frame(f, us, peer, "192.0.2.2", 17, 500, 500);
	CHECK(r2dp_nh_frame_ike_esp(f, n, &ip, &m) == 1 && ip == pip &&
	    memcmp(m, peer, 6) == 0, "unicast IKE/500 classified");
	n = frame(f, us, peer, "192.0.2.2", 17, 4500, 4500);
	CHECK(r2dp_nh_frame_ike_esp(f, n, &ip, &m) == 1, "unicast NAT-T/4500 classified");
	n = frame(f, us, peer, "192.0.2.2", 50, 0, 0);
	CHECK(r2dp_nh_frame_ike_esp(f, n, &ip, &m) == 1, "unicast ESP classified");
	n = frame(f, us, peer, "192.0.2.2", 17, 53, 53);
	CHECK(r2dp_nh_frame_ike_esp(f, n, &ip, &m) == 0, "DNS/UDP ignored");
	n = frame(f, us, peer, "192.0.2.2", 6, 500, 500);
	CHECK(r2dp_nh_frame_ike_esp(f, n, &ip, &m) == 0, "TCP ignored");
	n = frame(f, bcast, peer, "192.0.2.2", 50, 0, 0);
	CHECK(r2dp_nh_frame_ike_esp(f, n, &ip, &m) == 0, "broadcast ESP ignored");
	n = frame(f, us, peer, "192.0.2.2", 50, 0, 0);
	CHECK(r2dp_nh_frame_ike_esp(f, 30, &ip, &m) == 0, "truncated frame ignored");
	f[12] = 0x86; f[13] = 0xdd;
	CHECK(r2dp_nh_frame_ike_esp(f, n, &ip, &m) == 0, "non-IPv4 ethertype ignored");

	if (fails) { printf("nh_test: %d failures\n", fails); return 1; }
	puts("nh_test: OK");
	return 0;
}

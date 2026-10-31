/*
 * fwd/dp_nh.c -- per-peer next-hop table (see dp_nh.h).
 */
#include <string.h>

#include "dp_nh.h"

#define ETH_HLEN    14
#define ETHERTYPE_IPV4 0x0800
#define IPPROTO_ESP_ 50
#define IPPROTO_UDP_ 17

static int
ike_port(uint16_t p)
{
	return p == 500 || p == 4500;
}

int
r2dp_nh_frame_ike_esp(const uint8_t *f, size_t len, uint32_t *sip,
    const uint8_t **smac)
{
	const uint8_t *ip;
	size_t ihl;

	if (len < ETH_HLEN + 20)
		return 0;
	if (f[0] & 0x01)                      /* group dst: never learn */
		return 0;
	if (f[6] & 0x01)                      /* group src is bogus */
		return 0;
	if (((uint16_t)f[12] << 8 | f[13]) != ETHERTYPE_IPV4)
		return 0;
	ip = f + ETH_HLEN;
	if ((ip[0] >> 4) != 4)
		return 0;
	ihl = (size_t)(ip[0] & 0x0f) * 4;
	if (ihl < 20 || len < ETH_HLEN + ihl)
		return 0;
	if (ip[9] == IPPROTO_UDP_) {
		uint16_t sp, dp;
		if (len < ETH_HLEN + ihl + 8)
			return 0;
		sp = (uint16_t)(ip[ihl] << 8 | ip[ihl + 1]);
		dp = (uint16_t)(ip[ihl + 2] << 8 | ip[ihl + 3]);
		if (!ike_port(sp) && !ike_port(dp))
			return 0;
	} else if (ip[9] != IPPROTO_ESP_)
		return 0;
	memcpy(sip, ip + 12, 4);
	*smac = f + 6;
	return 1;
}

static uint64_t
mac_pack(const uint8_t mac[6])
{
	uint64_t v = 0;

	memcpy(&v, mac, 6);
	return v;
}

#define LD(p)     __atomic_load_n((p), __ATOMIC_RELAXED)
#define ST(p, v)  __atomic_store_n((p), (v), __ATOMIC_RELAXED)

/* Writer side of the seqlock around one entry update. */
static void
nh_write(struct r2dp_nh_tab *t, struct r2dp_nh *e, uint32_t ip, uint64_t mac)
{
	uint32_t s = t->seq;

	ST(&t->seq, s + 1);
	__atomic_thread_fence(__ATOMIC_RELEASE);
	ST(&e->ip, ip);
	ST(&e->mac, mac);
	ST(&e->used, 1u);
	__atomic_store_n(&t->seq, s + 2, __ATOMIC_RELEASE);
}

int
r2dp_nh_learn(struct r2dp_nh_tab *t, uint32_t ip, const uint8_t mac[6],
    uint64_t now)
{
	int free_i = -1, lru = 0, ret = 1;
	uint64_t m = mac_pack(mac);

	for (int i = 0; i < R2DP_NH_MAX; i++) {
		struct r2dp_nh *e = &t->e[i];
		if (!e->used) {
			if (free_i < 0)
				free_i = i;
			continue;
		}
		if (e->seen < t->e[lru].seen || !t->e[lru].used)
			lru = i;
		if (e->ip != ip)
			continue;
		e->seen = now;
		if (e->mac == m)
			return 0;
		nh_write(t, e, ip, m);        /* peer moved: relearn */
		return 2;
	}
	if (free_i < 0) {
		free_i = lru;                 /* full: evict least recently seen */
		ret = 3;
	}
	t->e[free_i].seen = now;
	nh_write(t, &t->e[free_i], ip, m);
	return ret;
}

int
r2dp_nh_lookup(const struct r2dp_nh_tab *t, uint32_t ip, uint8_t mac[6])
{
	for (;;) {
		uint32_t s = __atomic_load_n(&t->seq, __ATOMIC_ACQUIRE);
		uint64_t m = 0;
		int hit = 0;

		if (s & 1)
			continue;
		for (int i = 0; i < R2DP_NH_MAX; i++)
			if (LD(&t->e[i].used) && LD(&t->e[i].ip) == ip) {
				m = LD(&t->e[i].mac);
				hit = 1;
				break;
			}
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		if (LD(&t->seq) != s)
			continue;
		if (hit)
			memcpy(mac, &m, 6);
		return hit;
	}
}

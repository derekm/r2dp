/*
 * fwd/dp_nh.c -- IKE/ESP frame classifier for next-hop learning
 * (see dp_nh.h; the table is dpdk_nh.c).
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

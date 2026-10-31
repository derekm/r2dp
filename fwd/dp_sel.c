/*
 * fwd/dp_sel.c -- selector matching (see dp_sel.h).
 */
#include <string.h>
#include <arpa/inet.h>

#include "dp_sel.h"

/* One 32-bit masked compare instead of a variable-length memcmp plus a
 * partial-byte mask: same result for every prefix 0..32. */
static inline int
prefix_match(const struct r2dp_addr *sel, uint8_t pref, const uint8_t *a)
{
	uint32_t s, x, mask;

	if (sel->family != R2DP_AF_INET4 || pref > 32)
		return 0;
	if (!pref)
		return 1;
	memcpy(&s, sel->addr, 4);
	memcpy(&x, a, 4);
	mask = htonl(~0u << (32 - pref));
	return ((s ^ x) & mask) == 0;
}

int
r2dp_sel_match(const struct r2dp_sp *sp, const uint8_t *ip, size_t avail)
{
	size_t ihl;
	uint8_t proto;

	if (avail < 20 || (ip[0] >> 4) != 4)
		return 0;
	ihl = (size_t)(ip[0] & 0x0f) * 4;
	if (ihl < 20 || ihl > avail)
		return 0;
	proto = ip[9];
	if (sp->ul_proto != R2DP_PROTO_ANY && sp->ul_proto != proto)
		return 0;
	if (!prefix_match(&sp->sel_src, sp->pref_src, ip + 12) ||
	    !prefix_match(&sp->sel_dst, sp->pref_dst, ip + 16))
		return 0;
	if (sp->sel_src.port || sp->sel_dst.port) {
		uint16_t frag = (uint16_t)((ip[6] & 0x1f) << 8 | ip[7]);
		uint16_t s, d;   /* network order, as r2dp_addr.port */

		if (proto != 6 && proto != 17 && proto != 132)
			return 0;          /* no ports to compare */
		if (frag != 0 || avail < ihl + 4)
			return 0;          /* non-first fragment / truncated */
		memcpy(&s, ip + ihl, 2);
		memcpy(&d, ip + ihl + 2, 2);
		if (sp->sel_src.port && sp->sel_src.port != s)
			return 0;
		if (sp->sel_dst.port && sp->sel_dst.port != d)
			return 0;
	}
	return 1;
}

int
r2dp_sel_score(const struct r2dp_sp *sp)
{
	return (sp->pref_src + sp->pref_dst) * 4 +
	    (sp->sel_src.port ? 1 : 0) * 2 + (sp->sel_dst.port ? 1 : 0) * 2 +
	    (sp->ul_proto != R2DP_PROTO_ANY ? 1 : 0);
}

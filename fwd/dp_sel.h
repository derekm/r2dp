/*
 * fwd/dp_sel.h -- RFC 4301 selector matching for the r2dp dataplane.
 * Pure C (no DPDK) so it is unit-testable.  IPv4 only (the M1 dataplane).
 */
#ifndef R2DP_FWD_DP_SEL_H
#define R2DP_FWD_DP_SEL_H

#include <stddef.h>
#include <stdint.h>

#include "r2dp/proto.h"

/* Does the IPv4 packet at `ip` (`avail` contiguous bytes) match the policy's
 * selector: ul_proto, src/dst prefixes and, when the selector carries one,
 * src/dst ports?  A port-specific selector only matches TCP/UDP/SCTP
 * packets whose ports are visible (first fragment, header present);
 * anything else does not match it.  Returns 1/0. */
int r2dp_sel_match(const struct r2dp_sp *sp, const uint8_t *ip, size_t avail);

/* Specificity used to pick among several matching policies (higher wins):
 * prefix lengths dominate, then specified ports, then a specific ul_proto. */
int r2dp_sel_score(const struct r2dp_sp *sp);

#endif /* R2DP_FWD_DP_SEL_H */

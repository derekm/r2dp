/*
 * fwd/dp_nh.h -- egress ESP next-hop learning: frame classifier.
 *
 * Egress ESP must be unicast to the tunnel peer's MAC.  The MAC is learned
 * per peer IPv4 address, only from unicast frames that are IKE (UDP 500/4500)
 * or ESP and whose source IP is a configured tunnel peer, and is relearned
 * when it changes.  Egress to a peer with no learned MAC is dropped, never
 * broadcast.
 *
 * The table itself (dpdk_nh.h) is DPDK-backed; this header is the pure-C
 * frame classifier that feeds it, unit-testable without DPDK.
 */
#ifndef R2DP_FWD_DP_NH_H
#define R2DP_FWD_DP_NH_H

#include <stddef.h>
#include <stdint.h>

/* Classify an Ethernet frame.  Returns 1 if it is a unicast IPv4 frame
 * carrying ESP (proto 50) or UDP with source or destination port 500/4500,
 * filling *sip (raw wire order) and *smac; else 0. */
int r2dp_nh_frame_ike_esp(const uint8_t *f, size_t len, uint32_t *sip,
    const uint8_t **smac);

#endif /* R2DP_FWD_DP_NH_H */

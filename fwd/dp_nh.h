/*
 * fwd/dp_nh.h -- per-peer next-hop (L2) table for egress ESP.
 *
 * Egress ESP must be unicast to the tunnel peer's MAC.  The MAC is learned
 * per peer IPv4 address, only from unicast frames that are IKE (UDP 500/4500)
 * or ESP and whose source IP is a configured tunnel peer, and is relearned
 * when it changes.  Egress to a peer with no learned MAC is dropped, never
 * broadcast.  Pure C (no DPDK) so it is unit-testable.
 *
 * Concurrency: one writer (the lcore that receives on the outer port) and
 * any number of concurrent readers (the packet workers).  A table-wide
 * sequence counter (seqlock) lets a reader detect and retry a lookup that
 * overlapped a learn; every field is accessed with atomic loads/stores, so
 * a reader never sees a torn IP/MAC pair.
 */
#ifndef R2DP_FWD_DP_NH_H
#define R2DP_FWD_DP_NH_H

#include <stddef.h>
#include <stdint.h>

#define R2DP_NH_MAX 64

struct r2dp_nh {
	uint32_t ip;          /* raw wire-order IPv4 */
	uint32_t used;
	uint64_t mac;         /* 6 MAC bytes, in memory order, low bytes */
	uint64_t seen;        /* caller's clock at last learn/refresh (writer) */
};

struct r2dp_nh_tab {
	uint32_t       seq;   /* odd while the writer is updating */
	struct r2dp_nh e[R2DP_NH_MAX];
};

/* Classify an Ethernet frame.  Returns 1 if it is a unicast IPv4 frame
 * carrying ESP (proto 50) or UDP with source or destination port 500/4500,
 * filling *sip (raw wire order) and *smac; else 0. */
int r2dp_nh_frame_ike_esp(const uint8_t *f, size_t len, uint32_t *sip,
    const uint8_t **smac);

/* Learn/refresh ip -> mac at time `now` (any monotonic clock).  Returns 1
 * new, 2 changed, 0 unchanged.  When the table is full the least recently
 * seen entry is evicted (returns 3), so a stale peer never blocks a new
 * one. */
int r2dp_nh_learn(struct r2dp_nh_tab *t, uint32_t ip, const uint8_t mac[6],
    uint64_t now);

/* Copy ip's MAC to mac[] and return 1, or return 0 if unknown.  Safe
 * against a concurrent r2dp_nh_learn on another thread. */
int r2dp_nh_lookup(const struct r2dp_nh_tab *t, uint32_t ip, uint8_t mac[6]);

#endif /* R2DP_FWD_DP_NH_H */

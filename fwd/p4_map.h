/*
 * fwd/p4_map.h -- ctl SA parameters -> P4/SWX ipsec extern parameters.
 *
 * Pure functions, no DPDK, so the mapping is unit tested in every build
 * (tests/p4_map.c).  A request the extern cannot enforce is refused with
 * -EOPNOTSUPP before anything is allocated -- never silently downgraded
 * (P4 review P2, COMMITS C6).
 */
#ifndef R2DP_P4_MAP_H
#define R2DP_P4_MAP_H

#include <errno.h>
#include <stdint.h>

/* r2dp window semantics (both backends): a window of w accepts a sequence
 * number at distance 0..w-1 below the highest accepted one and refuses
 * distance >= w; w == 0 means anti-replay off.  librte_ipsec's window is
 * inclusive at its top (replay_win_sz = W accepts distance 0..W), and
 * W == 0 turns it off.  So w maps to W = w - 1, which is unrepresentable
 * for w == 1 (W = 0 would mean "off"): refuse it.  have_replay is 0 when
 * the extern carries no window at all (stock DPDK): only w == 0 is then
 * honest. */
static inline int
p4_replay_win(uint32_t w, int have_replay, uint32_t *win_sz)
{
	*win_sz = 0;
	if (w == 0)
		return 0;
	if (!have_replay || w == 1)
		return -EOPNOTSUPP;
	*win_sz = w - 1;
	return 0;
}

/* Feature gate for one SA install: replay window (inbound), ESN (the
 * extern builds ESN-off transforms) and NAT-T (needs the patched extern). */
static inline int
p4_sa_supported(int inbound, uint32_t window, int esn, int natt,
    int have_replay, int have_natt, uint32_t *win_sz)
{
	*win_sz = 0;
	if (esn)
		return -EOPNOTSUPP;
	if (natt && !have_natt)
		return -EOPNOTSUPP;
	if (!inbound)
		return 0;   /* outbound: the window is a receive-side property */
	return p4_replay_win(window, have_replay, win_sz);
}

/* The P4 SPD tables (OUT and IN) key on protocol and address prefixes
 * only.  A port-qualified selector would be widened to every port: for a
 * BYPASS that forwards cleartext a broader PROTECT/DISCARD should have
 * caught, for PROTECT/DISCARD it captures unrelated traffic.  Refuse any
 * nonzero selector port rather than install a different policy than the
 * one asked for (COMMITS C7, P4 review P4). */
static inline int
p4_sp_supported(uint16_t sport, uint16_t dport)
{
	return (sport || dport) ? -EOPNOTSUPP : 0;
}

/* Egress SA choice for an OUT PROTECT policy among endpoint matches, the
 * same rule as main's sa_by_policy (dpdk_spd.c): an SA whose nonzero
 * reqid equals the policy's outranks every other endpoint match, and the
 * newest install (highest gen) wins within a class.  racoon2 sends reqid 0,
 * so the common case stays endpoint + newest (P4 review P4). */
static inline int
p4_sa_outranks(uint32_t sp_reqid, uint32_t reqid, uint64_t gen,
    uint32_t best_reqid, uint64_t best_gen)
{
	int c = sp_reqid && reqid == sp_reqid;
	int bc = sp_reqid && best_reqid == sp_reqid;

	return c != bc ? c > bc : gen > best_gen;
}

/* The extern keeps no per-SA byte counter (p4_sa_bytes reports none), so
 * ctl's soft/hard byte expiry never fires for this backend.  A finite
 * byte lifetime is refused rather than acknowledged as an infinite SA
 * (P4 review P8).  Time lifetimes are enforced by ctl's expiry loop. */
static inline int
p4_lft_supported(uint64_t hard_bytes, uint64_t soft_bytes)
{
	return (hard_bytes || soft_bytes) ? -EOPNOTSUPP : 0;
}

/* The classification regarrays the spec's parser/apply read: direction
 * per input port (0 outer, 1 inner) and the extern's port (2) for each
 * leg.  They default to 0, so a lost write misclassifies traffic; every
 * write is required (P4 review P10).  p4_regs_program stops at the first
 * failure, reports which entry through *bad, and returns its error. */
struct p4_reg { const char *name; uint32_t idx; uint64_t val; };

static const struct p4_reg p4_regs[] = {
	{ "direction",               0, 0 },
	{ "direction",               1, 1 },
	{ "ipsec_port_in_inbound",   0, 2 },
	{ "ipsec_port_in_outbound",  0, 2 },
	{ "ipsec_port_out_inbound",  0, 2 },
	{ "ipsec_port_out_outbound", 0, 2 },
};
#define P4_NREGS (sizeof(p4_regs) / sizeof(p4_regs[0]))

static inline int
p4_regs_program(int (*wr)(void *ctx, const char *name, uint32_t idx,
    uint64_t val), void *ctx, unsigned *bad)
{
	for (unsigned i = 0; i < P4_NREGS; i++) {
		int rc = wr(ctx, p4_regs[i].name, p4_regs[i].idx, p4_regs[i].val);
		if (rc) {
			*bad = i;
			return rc < 0 ? rc : -EIO;
		}
	}
	return 0;
}

#endif

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

#endif

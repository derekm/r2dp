/*
 * r2dp -> Linux XFRM (NETLINK_XFRM) translation: the "kernel dataplane" backend.
 *
 * Plugs into the shared control-plane engine as hooks, so every request is
 * installed in the kernel *before* the client is told it succeeded, and the
 * kernel's own errno is what the client sees when it refuses.  This makes the
 * kernel a conformance reference for the DPDK forwarder: same r2dp requests in,
 * same observable behaviour expected out.
 */
#ifndef R2DP_KFWD_XFRM_H
#define R2DP_KFWD_XFRM_H

#include "r2dp/cp.h"

/* Open the netlink socket (ext-ack enabled, 3 s receive timeout). 0 or -errno. */
int kx_open(int verbose);
void kx_close(void);

/* Hooks for r2dp_cp_new().  Valid after kx_open(). */
const struct r2dp_cp_hooks *kx_hooks(void);

/*
 * Ask the kernel what it can actually do (crypto algorithms autoload on first
 * use, so /proc/crypto is not reliable): try a throwaway state per transform on
 * reserved TEST-NET addresses and delete it again.  Fills caps->enc/integ bitmaps
 * and features.  Returns the number of transforms that worked.
 */
int kx_probe_caps(struct r2dp_cp_caps *caps);

/* Advertise everything the translation table knows, without asking the kernel. */
void kx_default_caps(struct r2dp_cp_caps *caps);

#endif

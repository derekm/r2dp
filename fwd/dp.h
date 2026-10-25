/*
 * fwd/dp.h -- dataplane abstraction for the r2dp forwarder.
 *
 * ctl.c (the r2dp control server) is hardware-agnostic: it applies SAD/SPD
 * to the dataplane through this small vtable.  The DPDK dataplane
 * (fwd/dp_dpdk.c) implements it with rte_ipsec_sad / rte_acl and the
 * run-to-completion packet loop; a P4/XDP2 backend would implement the same
 * interface behind the identical r2dp socket.
 *
 * MT: the control thread and the packet threads share the dataplane.  The
 * implementation must serialize (usually an rte_spinlock or RCU) so a
 * mid-flight SA_ADD never races a lookup.
 */
#ifndef R2DP_FWD_DP_H
#define R2DP_FWD_DP_H

#include <stddef.h>
#include <stdint.h>

#include "r2dp/proto.h"

struct fwd_dp;

/* sa_add `add` flag: the SA protects traffic TO us (its SPI was allocated by
 * our GETSPI), so install it for ingress/decrypt in the inbound SAD.  Without
 * it an add is an outbound (egress/encrypt) SA for the SPD-driven egress leg. */
#define FWD_DP_SA_INBOUND 0x2

struct fwd_dp_ops {
	/* Fill the dataplane's supported-crypto bitmaps (enc_caps/integ_caps)
	 * in the fwd_dp, not a const member of this ops table. */
	void (*caps)(struct fwd_dp *dp);

	/* Install (add!=0) or remove (add==0) an SA in the dataplane.
	 * `blob` is the AEAD key material (cipher key || salt, enckeylen
	 * bytes) when present.  The dataplane keeps its own copy.  `add` may
	 * carry FWD_DP_SA_INBOUND (see above). */
	int (*sa_add)(struct fwd_dp *dp, int add,
	    const struct r2dp_sa *sa, const void *blob, size_t blen);

	/* Install or remove a policy.  ->sp_add returns the assigned slid
	 * (for SP_ADD with slid=0) via sp->slid. */
	int (*sp_add)(struct fwd_dp *dp, struct r2dp_sp *sp);
	int (*sp_del)(struct fwd_dp *dp, const struct r2dp_sp *sp);

	/* Optional: current byte count crypted on the SA keyed by (spi, dip),
	 * for byte-lifetime EXPIRE.  Returns -1 if the SA is unknown. */
	int64_t (*sa_bytes)(struct fwd_dp *dp, uint32_t spi, uint32_t dip);

	/* Optional: start/stop the datapath packet threads. */
	int (*start)(struct fwd_dp *dp);
	void (*stop)(struct fwd_dp *dp);
};

struct fwd_dp {
	const struct fwd_dp_ops *ops;
	void *priv;             /* backend private state */
	uint32_t flags;

	/* Capability bitmaps the dataplane actually supports. */
	uint32_t caps_bits_enc[8];
	uint32_t caps_bits_integ[8];
};

/* Defaults: zero -> no backend (ctl.c still answers protocol). */
void fwd_dp_init(struct fwd_dp *dp);

/* DPDK backend (fwd/dp_dpdk.c).  argc/argv after DPDK EAL init. */
int fwd_dp_dpdk_probe(struct fwd_dp *dp, int *argc, char **argv[],
    const char *sockpath, int verbose);

#endif /* R2DP_FWD_DP_H */

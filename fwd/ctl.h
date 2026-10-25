/*
 * fwd/ctl.h -- r2dp control-plane server (hardware-agnostic state +
 * entry points).  Implementation in fwd/ctl.c.
 */
#ifndef R2DP_FWD_CTL_H
#define R2DP_FWD_CTL_H

#include <stdint.h>

#include "r2dp/proto.h"
#include "dp.h"

#define FWD_MAXSA 1024
#define FWD_MAXSP 1024

/* Larval (GETSPI-reserved) SAs are held this long before reaping; the kernel
 * treats a reserved-but-never-confirmed SPI as garbage after ~30 s. */
#define R2DP_LARVAL_TTL_S 30

struct fwd_sa_ent {
	int used, larval;
	time_t larva_at;              /* when a larval reservation was made */
	struct r2dp_sa sa;
};
struct fwd_sp_ent { int used; struct r2dp_sp sp; };

struct fwd_ctl {
	struct fwd_dp dp;                 /* dataplane backend vtable */
	struct fwd_sa_ent sad[FWD_MAXSA]; /* in-process SAD (M1 scale) */
	struct fwd_sp_ent spd[FWD_MAXSP];
	uint32_t next_slid;
	uint64_t epoch;
	int verbose;
};

/* Initialize the control server against a dataplane vtable. */
int fwd_ctl_init(struct fwd_ctl *c, const char *sockpath, int verbose);

/* Serve the r2dp socket until an error; blocking. */
int fwd_ctl_run(struct fwd_ctl *c, const char *sockpath);

#endif /* R2DP_FWD_CTL_H */

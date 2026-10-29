/*
 * r2dp control-plane engine: the protocol state machine shared by every
 * forwarder.  It owns the canonical SAD/SPD (so EEXIST/ENOENT, SPI
 * allocation, policy ids and dump streaming behave identically everywhere)
 * and calls hooks when state a dataplane cares about changes.
 *
 *   mock forwarder : no hooks
 *   DPDK forwarder : hooks program the datapath tables
 */
#ifndef R2DP_CP_H
#define R2DP_CP_H

#include "r2dp/client.h"

struct r2dp_cp_hooks {
	void *ctx;
	/* SA became usable (ADD/UPDATE).  Return 0 or -errno: on error the
	 * client gets that status and the control-plane state is unchanged. */
	int  (*sa_set)(void *ctx, const struct r2dp_sa *sa,
	               const uint8_t *enckey, const uint8_t *authkey);
	void (*sa_del)(void *ctx, const struct r2dp_sa *sa);
	/* SP added or replaced (R2DP_SPF_UPDATE). slid is already assigned. */
	int  (*sp_set)(void *ctx, const struct r2dp_sp *sp);
	void (*sp_del)(void *ctx, const struct r2dp_sp *sp);
};

struct r2dp_cp_caps {
	uint32_t features;       /* R2DP_FEAT_* */
	uint32_t enc_caps[8];
	uint32_t integ_caps[8];
};

struct r2dp_cp_opts {
	const char *name;        /* log prefix, e.g. "mockfwd" */
	int verbose;             /* log each request to stderr */
	int echo_keys;           /* tests only: return keys in completions */
	int sw_lifetimes;        /* engine enforces time lifetimes itself via r2dp_cp_tick() (mock / forwarders
	                          * without their own accounting).  Backends that count packets/bytes leave this
	                          * off and call r2dp_cp_sa_expired() themselves. */
};

/* Forwarder-side usage figures reported with an expiry (all optional). */
struct r2dp_sa_counters {
	uint64_t alloc;          /* packets processed.  iked IGNORES a soft expiry with alloc == 0 (unused SA) */
	uint64_t use;            /* wall-clock time of last use, 0 = never */
	uint64_t bytes;
};

struct r2dp_cp;
struct r2dp_cp *r2dp_cp_new(const struct r2dp_cp_hooks *h,
                            const struct r2dp_cp_caps *caps,
                            const struct r2dp_cp_opts *opts);
void r2dp_cp_free(struct r2dp_cp *cp);

/* Handle one validated request from client fd; sends the completion(s). */
void r2dp_cp_handle(struct r2dp_cp *cp, int fd, const struct r2dp_msg *m);

/*
 * Unsolicited event: tell the IKE clients an SA hit a lifetime limit (kind =
 * R2DP_EXPIRE_SOFT or _HARD).  Delivered best-effort and without blocking, to
 * clients that said HELLO with role IKED or UNSPEC (never SPMD/CTL).  For HARD
 * the engine forgets the SA: the dataplane must already have stopped using it,
 * and no sa_del hook is called.  ctr may be NULL (reported as alloc = 1).
 * Returns the number of clients the event was queued to, or -ENOENT.
 */
int r2dp_cp_sa_expired(struct r2dp_cp *cp, const struct r2dp_sa *key, int kind,
                       const struct r2dp_sa_counters *ctr);

/* With opts.sw_lifetimes: enforce time lifetimes.  Call about once a second. */
void r2dp_cp_tick(struct r2dp_cp *cp);

/* A client connection went away (the server loops call this; custom loops must too). */
void r2dp_cp_client_gone(struct r2dp_cp *cp, int fd);

/*
 * For event loops that do their own receiving (e.g. io_uring): validate the n
 * bytes in m and run the request.  Returns 0 to keep the client, or a negative
 * errno (-EPROTO ...) when the connection should be dropped.  Unknown-but-sane
 * message types are answered with ENOSYS and return 0, like r2dp_srv_poll().
 */
int r2dp_cp_dispatch(struct r2dp_cp *cp, int fd, const struct r2dp_msg *m, size_t n);

/* Read-only lookup of a committed (non-larval) SA, for dataplane resync. */
int r2dp_cp_foreach_sa(struct r2dp_cp *cp,
                       void (*fn)(void *, const struct r2dp_sa *, const uint8_t *, const uint8_t *),
                       void *arg);

/* ---- multi-client server socket ---------------------------------------- */
struct r2dp_srv;
struct r2dp_srv *r2dp_srv_new(const char *path);           /* NULL on error, errno set */
int  r2dp_srv_fd(const struct r2dp_srv *s);                 /* listen fd (for external pollers) */
/* Poll listen+client sockets for up to timeout_ms (0 = non-blocking) and run
 * every pending request through cp.  Returns requests handled, or -errno. */
int  r2dp_srv_poll(struct r2dp_srv *s, struct r2dp_cp *cp, int timeout_ms);
void r2dp_srv_free(struct r2dp_srv *s);

#endif

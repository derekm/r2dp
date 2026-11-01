/*
 * fwd/dpdk_nh.h -- per-peer next-hop (L2) table for egress ESP.
 *
 * Maps a tunnel peer's outer IPv4 address (the outer header is IPv4-only
 * in this data path) to the MAC learned from its IKE/ESP frames (see
 * dp_nh.h for what is learned).  One table per forwarder, shared by every
 * lcore, with no limit on the number of tunnels: it grows.
 *
 * Loss-free by construction -- a learned entry is never removed by
 * capacity pressure, only by an explicit r2dp_nh_del (the policy snapshot
 * rebuild calls it when the last SA/policy naming the peer is deleted) or replaced in place by a MAC change:
 *
 *   - Readers (packet workers) acquire-load the published table pointer
 *     once per burst and look up lock-free (rte_hash with
 *     RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF, one bulk lookup per burst).
 *     The MAC is the entry's 64-bit data word: nothing to dereference,
 *     no torn reads.  Readers never take a lock and never wait.
 *   - The learner (the lcore receiving on the outer port) inserts or
 *     updates in place under t->lock taken with a trylock; if the lock is
 *     busy or the table is full it posts the request to an MP/SC ring and
 *     moves on.  It never blocks and never builds a table.
 *   - A maintenance thread (r2dp_nh_start; a control thread, not a packet
 *     lcore) drains the ring and, once the table is 75% full or an insert
 *     hit -ENOSPC, builds a table twice the size off the data path, copies
 *     every entry into it under t->lock (so no insert can race the copy),
 *     publishes it with a release store, and frees the old one only after
 *     an rte_rcu_qsbr grace period -- no reader can still be inside it.
 *   - If growth fails (allocation), the current table keeps serving every
 *     entry it has; requests that do not fit stay on a pending list that
 *     is retried on every pass (stats: pending, grow_fail).  If even the
 *     ring/pending list is full the learn is refused and counted (q_drop);
 *     the peer's next IKE/ESP frame offers it again.
 *   - Deleted key slots are recycled only after a grace period
 *     (rte_hash_rcu_qsbr_add, defer-queue mode, on the forwarder's QSBR).
 */
#ifndef R2DP_FWD_DPDK_NH_H
#define R2DP_FWD_DPDK_NH_H

#include <pthread.h>
#include <stdint.h>

#include <rte_hash.h>
#include <rte_rcu_qsbr.h>
#include <rte_ring.h>
#include <rte_spinlock.h>

#define R2DP_NH_DEFAULT_SIZE 1024u       /* initial capacity, peers */
#define R2DP_NH_MIN_SIZE     8u
#define R2DP_NH_MAX_CAP      (1u << 24)  /* growth stops here */
#define R2DP_NH_PEND_MAX     4096u       /* learns parked for the next pass */
#define R2DP_NH_RING_SZ      4096u

struct r2dp_nh_req {
	uint32_t ip;
	uint32_t pad;
	uint64_t mac;   /* packed data word */
};

struct r2dp_nh_tab {
	struct rte_hash    *h;        /* published; readers acquire-load it */
	uint32_t            cap;      /* capacity of h */
	uint32_t            n;        /* entries in h */
	struct rte_rcu_qsbr *rcu;
	rte_spinlock_t      lock;     /* serializes every writer */
	struct rte_ring    *req;      /* learner -> maintenance thread */
	struct r2dp_nh_req *pend;     /* maintenance thread only */
	uint32_t            npend;
	int                 want_grow;
	uint32_t            gen;
	int                 socket;
	char                name[24];
	pthread_t           thr;
	int                 thr_run;
	/* stats */
	uint64_t            n_grow, n_grow_fail, n_q_drop;
	/* test hook: fail this many growth attempts as if out of memory */
	uint32_t            inject_grow_fail;
};

/* Create the table with room for `size` peers (0 = default; it grows
 * from there), attached to `rcu` (NULL: no concurrent readers).
 * Returns 0 or -errno. */
int r2dp_nh_init(struct r2dp_nh_tab *t, const char *name, uint32_t size,
    struct rte_rcu_qsbr *rcu, int socket);
/* Start / stop the maintenance thread (runs r2dp_nh_maint every ms). */
int r2dp_nh_start(struct r2dp_nh_tab *t);
void r2dp_nh_stop(struct r2dp_nh_tab *t);
void r2dp_nh_free(struct r2dp_nh_tab *t);

/* One maintenance pass: drain learn requests, grow if due, retry pending
 * learns, free a replaced table after a grace period.  May block on the
 * grace period: never call it from a QSBR reader thread. */
void r2dp_nh_maint(struct r2dp_nh_tab *t);

/* Learn ip (raw wire order) -> mac.  Never blocks.  Returns 0 unchanged,
 * 1 new, 2 changed (in place), 4 queued for the maintenance thread, -1
 * refused (queue full; counted, offered again by the peer's next frame). */
int r2dp_nh_learn(struct r2dp_nh_tab *t, uint32_t ip, const uint8_t mac[6]);

/* Explicit removal (peer deleted by the control plane).  Returns 1 if it
 * was present. */
int r2dp_nh_del(struct r2dp_nh_tab *t, uint32_t ip);

/* Copy ip's MAC to mac[] and return 1, or return 0 if unknown. */
int r2dp_nh_lookup(const struct r2dp_nh_tab *t, uint32_t ip, uint8_t mac[6]);

/* Look up n (<= RTE_HASH_LOOKUP_BULK_MAX) addresses at once: mac[i] gets
 * ip[i]'s MAC (6 bytes, low bytes of the word in memory order) and bit i
 * of the return value is set when it is known. */
uint64_t r2dp_nh_lookup_bulk(const struct r2dp_nh_tab *t, const uint32_t *ip,
    unsigned n, uint64_t *mac);

#endif /* R2DP_FWD_DPDK_NH_H */

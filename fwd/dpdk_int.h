/*
 * fwd/dpdk_int.h -- types and cross-module prototypes shared by the DPDK
 * data-plane modules (dp_dpdk.c, dpdk_sad.c, dpdk_spd.c, dpdk_esp.c,
 * dpdk_stats.c) and by the white-box tests and bench that link them.
 */
#ifndef R2DP_DPDK_INT_H
#define R2DP_DPDK_INT_H

#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_esp.h>
#include <rte_ipsec.h>
#include <rte_ipsec_sa.h>
#include <rte_ipsec_sad.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <rte_cryptodev.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_rcu_qsbr.h>
#include "qsbr_sync.h"
#include <rte_acl.h>
#include <rte_ring.h>
#include <rte_hash_crc.h>
#include <rte_hash.h>

#include "r2dp/client.h"
#include "dp.h"
#include "ctl.h"
#include "dp_gcm.h"
#include "dp_nh.h"
#include "dpdk_nh.h"
#include "dp_sel.h"
#include <signal.h>

#define MEMPOOL_CACHE 256
#define MEMPOOL_SIZE  16384
/* SA and SP tables are chunked and grow on demand (dpdk_sad.c): a chunk,
 * once published, never moves or goes away while the data plane runs, so
 * a worker's pointer into it stays valid across growth. */
#define DP_CHUNK      1024u          /* entries per chunk */
#define DP_MAX_CHUNKS 4096u          /* 4M SAs / 4M SPs */
#define DP_SAD_INIT   1024u          /* initial inbound SAD capacity */
#define DP_SESS_POOL  2048u          /* crypto sessions per session pool */
#define DP_MAX_SESS_POOLS 2048u
#define DP_RING_SZ    1024  /* cross-post ring, per direction, per worker */
#define BURST_SZ      128
#define TAP_IF_DEFAULT "r2dp-tap"

#define NATT_PORT 4500             /* RFC 3948 ESP-in-UDP / IKE float port */
#define RP_BITS  R2DP_MAX_REPLAY_WIN  /* >= the largest window ctl accepts */
#define RP_WORDS (RP_BITS / 64)

struct dp_sa {
	struct rte_ipsec_sa *sa;      /* opaque, allocated from the ipsec lib */
	struct rte_ipsec_session sess;/* ipsec session bound to the crypto dev */
	struct rte_cryptodev_sym_session *cses;   /* crypto sym session */
	uint32_t           spi;      /* host order (ntohl of the wire SPI) */
	uint32_t           dip;      /* RAW wire-order addr bytes (addr4_to_u32
	                              * memcpy, NOT byteswapped -- the SAD key
	                              * and the lookup both use this numeric) */
	uint32_t           reqid;    /* egress linkage: SP with same reqid uses
	                              * this SA to encrypt (outbound) */
	uint32_t           srca, dsta; /* tunnel src/dst endpoints, raw wire bytes
	                              * (addr4_to_u32 memcpy).  racoon2 sends
	                              * reqid=0 for every SP/SA, so egress SA
	                              * selection must fall back to matching the
	                              * policy's tunnel endpoints (H3). */
	uint8_t            proto;
	uint8_t            used;
	uint8_t            inbound;  /* in the inbound SAD (our GETSPI) */
	uint8_t            natt;     /* R2DP_NATT_*; ESP-in-UDP demux (NAT-T) */
	uint8_t            owner;    /* the only worker that processes it */
	uint16_t           natt_sport, natt_dport; /* network order; egress UDP */
	uint64_t           gen;      /* install generation (monotonic): the
	                              * newest of several SAs for one tunnel is
	                              * the post-rekey SA egress must use */
	uint64_t           hard_bytes; /* hard byte lifetime, 0 = none: a packet
	                              * that would reach it is not forwarded */
	uint64_t           hard_deadline; /* unix seconds, 0 = no hard time.
	                              * Worker drops at or past it; ctl still
	                              * sends EXPIRE. */
	uint8_t            expire_kicked; /* 1 after the first data-path kick */
	uint64_t           bytes;    /* total bytes forwarded on this SA (soft/hard
	                              * byte lifetime accounting, young seq) */
	/* Our own anti-replay window (inbound SAs, worker-only state), checked
	 * after the ICV verified and before rte_ipsec_pkt_process.  librte_ipsec
	 * (24.11 and current main) records the window bit in a uint32_t
	 * (esn_inb_update_sqn: `uint32_t bit = (uint64_t)1 << (sqn & 63)`), so
	 * bits 32..63 of every bucket are never set and a replay of any
	 * sequence number with (sqn & 63) >= 32 is accepted.  This window is
	 * authoritative; rte_ipsec's stays as a second line. */
	uint64_t           rp_top;   /* highest accepted (64-bit, ESN-expanded) */
	uint64_t           rp_map[RP_WORDS]; /* bit (seq % RP_BITS) seen */
	uint32_t           rp_w;     /* window (packets), 0 = off, <= RP_BITS */
	uint8_t            rp_esn;   /* SA uses extended sequence numbers */
	uint32_t           idx;      /* own slot number (sa_at(d, idx) == this) */
	/* Crypto ops a stuck device still holds for this SA's session (one
	 * per worker quarantine, worker-written).  A retired SA whose session
	 * is pinned is not freed: it stays a zombie slot (ctl-only flag) until
	 * the device has handed every op back (WORKER W2). */
	uint32_t           pins;
	uint8_t            zombie;
};

/* SPD entry mirror for the egress (outbound) worker: populated by dpd_sp_add/
 * dpd_sp_del so worker_inner can select a policy without touching ctl.  M1:
 * linear, exact/prefix selector match on (dir=OUT, sel_src/sel_dst, proto). */
struct dp_sp_ent {
	/* Immutable policy copy, published with a release store and read by
	 * the worker with an acquire load (sp_load).  Replaced/removed by
	 * swapping the pointer, waiting a QSBR grace period, then freeing the
	 * old copy, so the worker never sees a torn or freed policy (M4). */
	struct r2dp_sp *sp;
	uint64_t ver;            /* unique per stored copy (ctl, d->lock) */
};


/* Policy snapshot (SPD view of the worker).  Built by the control thread
 * under d->lock whenever an SA or SP changes, published with a release
 * store, and freed only after a QSBR grace period, so the worker reads a
 * consistent, immutable view with one acquire load per burst.
 *
 * OUT policies are pre-sorted most-specific first (r2dp_sel_score desc,
 * sp_tab slot asc as the tie-break, i.e. the same winner as a full scan) and
 * each PROTECT policy is BOUND to its EGRESS SA here, at control time
 * (sa_by_policy), so the packet path never scans the SA table.  The binding
 * records the SA's install generation: if the slot has since been retired or
 * reused the generations differ and the packet is dropped (fail closed)
 * until the next rebuild. */
/* Drop reasons (n_drop == sum of n_dropr[]); dumped on SIGUSR1. */
enum dp_drop {
	DR_MALFORMED,       /* runt / bad IHL / bad ESP framing */
	DR_NO_SA_IN,        /* ESP with no inbound SA (SAD miss) */
	DR_NO_SA_OUT,       /* PROTECT policy matched, no egress SA (fail closed) */
	DR_POLICY_DISCARD,  /* DISCARD policy */
	DR_INNER_SEL,       /* decrypted inner packet outside the SA's IN policy */
	DR_CRYPTO_FAIL,     /* crypto op failed: ICV/auth failure, PMD error */
	DR_REPLAY,          /* authenticated, but a replay or left of the window */
	DR_IPSEC_REJECT,    /* rte_ipsec prepare/process rejected (window, ...) */
	DR_CRYPTO_ENQ,      /* cryptodev queue full past the spin budget */
	DR_NOMEM,           /* op pool, headroom, output array */
	DR_NO_NEXTHOP,      /* egress ESP with no learned peer MAC */
	DR_CLEAR_OUTER,     /* non-IKE/ARP cleartext on the outer side */
	DR_ESP_ON_INNER,    /* ESP arriving on the plaintext side */
	DR_TX_FULL,         /* tx ring full */
	DR_CRYPTO_STUCK,    /* cryptodev stopped completing ops (see crypto_run) */
	DR_ENCAP,           /* ESP vs ESP-in-UDP framing does not match the SA */
	DR_STEER,           /* SA owned by another worker, or worker ring full */
	DR_TOO_BIG,         /* ESP packet would exceed the outer port's MTU */
	DR_V6_POLICY,       /* inner IPv6 while IPv6 policies exist (no v6 ESP) */
	DR_EXPIRED,         /* SA past its hard byte lifetime (dead) */
	DR_NUM
};
#define DROP(w, r, n) do { uint64_t n_ = (n); (w)->n_drop += n_; \
	(w)->n_dropr[(r)] += n_; } while (0)

#ifndef DP_MAX_WK
#define DP_MAX_WK 8       /* packet workers (-n); same default as dp.h */
#endif

struct dpdk_priv;

/* One packet worker.  Everything here is written by that lcore only; the
 * stats dump sums the counters.  Each worker has its own port TX queue
 * and cryptodev queue pair, polls RX queue `id`, and in multi-worker mode
 * also dequeues two MP/SC rings of packets cross-posted by other workers. */
struct dp_wk {
	struct dpdk_priv   *d;
	unsigned            id;
	unsigned            lcore;
	uint16_t            txq;      /* port TX queue */
	uint16_t            cqp;      /* cryptodev queue pair */
	struct rte_ring    *ring_o;   /* outer (ESP side) frames, multi-worker */
	struct rte_ring    *ring_i;   /* inner (plaintext) frames, multi-worker */
	uint64_t            n_rx, n_tx, n_esp, n_ike, n_drop;
	uint64_t            n_dropr[DR_NUM]; /* n_drop split by reason */
	/* Ops a stuck cryptodev still owns.  They are never put back to cop_mp
	 * while the device holds them; crypto_run drains them (freeing their
	 * mbufs) before it enqueues anything new, so a late completion can
	 * never be mistaken for the current batch. */
	uint32_t            cq_stale;
	struct dp_sa       *cq_stale_sa; /* the SA whose session cq_stale's ops
	                              * use (pinned while cq_stale > 0) */
	uint64_t            n_crypto_stuck;  /* times the device stopped completing */
	uint64_t            n_natt_keepalive; /* RFC 3948 keepalives consumed */
	uint64_t            n_misplaced; /* outer ESP that arrived on a queue
	                              * other than its SA owner's and was
	                              * cross-posted: reordering risk (REPLAY R1) */
} __rte_cache_aligned;

#define PEER_HSZ_MIN 4096 /* peer hash slots: power of two, >= 4x peers */

struct dp_pol {
	const struct r2dp_sp *sp;
	int32_t  sa_idx;          /* bound EGRESS SA slot, -1 = none */
	uint64_t sa_gen;          /* that slot's gen at bind time */
	int      score;           /* r2dp_sel_score(sp) */
	int      slot;            /* sp_tab slot (tie-break) */
	uint64_t ver;             /* dp_sp_ent.ver: identity for dp_acl */
	/* the selector compiled against struct acl_key (wire order), for the
	 * delta list / dead-rule scan; v4 = 0: matches nothing (as in rte_acl) */
	uint32_t src, smask, dst, dmask;
	uint16_t sport, dport;    /* 0 = any */
	uint8_t  proto;           /* 0 = any */
	uint8_t  v4;
};

/* An rte_acl OUT classifier, shared by successive snapshots while the
 * policy set changes by little (refs: snapshots holding it, ctl-only).
 * Rule r (userdata r+1) was built for a policy copy identified by its
 * dp_sp_ent.ver (never reused, unlike a freed pointer); a snapshot maps it to
 * its own out[] index through acl_map (-1: policy gone = dead rule). */
struct dp_acl {
	struct rte_acl_ctx *ctx;
	uint32_t n;
	uint64_t *sorted;         /* (policy ver, rule) pairs by ver */
	uint32_t refs;
};

/* Policies added since the classifier was built are matched by a short
 * linear scan (delta); rules of deleted/replaced policies are dead and a
 * hit on one falls back to a scan of out[].  Above DP_ACL_DELTA
 * delta+dead the classifier is rebuilt; it is also compacted when the
 * policy set has been idle for DP_ACL_IDLE_MS. */
#define DP_ACL_DELTA    32
#define DP_ACL_IDLE_MS  200

struct dp_spd {
	uint32_t       nout;
	struct dp_pol *out;       /* OUT policies, most specific first */
	struct dp_acl *acl;       /* OUT classifier (NULL: none) */
	int32_t       *acl_map;   /* acl rule -> out[] index, -1 = dead */
	uint32_t       ndead;     /* dead acl rules */
	uint32_t       ndelta;
	uint32_t      *delta;     /* out[] indices not in the classifier */
	int            v6_out;    /* some OUT PROTECT/DISCARD has an IPv6 selector */
	/* Inbound (RFC 4301 s5.2) check, indexed by SA slot: the IN/FWD PROTECT
	 * policies whose tunnel endpoints/reqid fit that SA are
	 * in_pol[in_off[slot] .. in_off[slot+1]), valid while the slot's gen
	 * still equals in_gen[slot] (else the worker falls back to a scan). */
	uint32_t       in_cap;              /* SA slots indexed below */
	uint32_t      *in_off;              /* in_cap + 1 */
	uint64_t      *in_gen;              /* in_cap */
	const struct r2dp_sp **in_pol;
	/* Tunnel peers (far ends of SAs and PROTECT policies), open addressing,
	 * 0 = empty; peer_zero records 0.0.0.0 itself. */
	uint32_t      *peer;
	uint32_t       peer_mask;           /* slots - 1 (power of two) */
	int            peer_zero;
};

/* rte_acl key for the OUT SPD.  Addresses/ports are raw wire order (rte_acl
 * classifies network-order input against host-order rules).  Ports are
 * filled only when they are comparable -- TCP/UDP/SCTP, first fragment,
 * header present -- exactly when r2dp_sel_match compares them; otherwise
 * they are 0.  A port selector is never 0 (0 means "any"), so a
 * port-specific rule can never match a fragment or a portless protocol. */
struct acl_key {
	uint8_t  proto;
	uint8_t  pad[3];
	uint32_t src, dst;
	uint16_t sport, dport;
};
enum { AF_PROTO, AF_SRC, AF_DST, AF_SPORT, AF_DPORT, AF_NUM };
RTE_ACL_RULE_DEF(dp_acl_rule, AF_NUM);

/* Worker-side accessors: acquire pairs with the ctl-side release publish. */
static inline const struct r2dp_sp *
sp_load(const struct dp_sp_ent *e)
{
	return __atomic_load_n(&e->sp, __ATOMIC_ACQUIRE);
}

/* An SA slot is visible to the worker only after its release publish. */
static inline int
sa_live(const struct dp_sa *ds)
{
	return __atomic_load_n(&ds->used, __ATOMIC_ACQUIRE);
}

struct dpdk_priv {
	int                 port_id;      /* outer tap (ESP side) */
	int                 inner_port;   /* inner tap (plaintext side) */
	struct rte_mempool *pool;
	struct rte_mempool *sess_mp;   /* crypto session mempool (first) */
	struct rte_mempool *sess_more[DP_MAX_SESS_POOLS]; /* added on demand */
	uint32_t            n_sess_more;
	struct rte_mempool *cop_mp;    /* crypto operation mempool */
	struct rte_hash    *sad;      /* inbound SAD (dp_sad_*); published:
				       * workers acquire-load it */
	uint32_t            sad_cap;  /* SAs it was sized for; 0 = fixed */
	uint32_t            sad_n;    /* inbound SAs in it */
	uint32_t            n_zombie; /* retired SA slots awaiting unpin (ctl) */
	struct rte_cryptodev_info cdev_info;
	uint8_t             cdev_id;
	int                 have_cdev;
	rte_spinlock_t      lock;
	struct rte_rcu_qsbr *rcu;   /* H5: QSBR for the ctl<->worker SA/SP handoff */
	unsigned            rcu_tid; /* worker thread id registered with the QSBR */
	struct dp_sa       *sa_chunk[DP_MAX_CHUNKS];
	struct dp_sp_ent   *sp_chunk[DP_MAX_CHUNKS];
	uint32_t            sa_cap, sp_cap; /* published (release) slot counts */
	uint32_t            sa_n, sp_n;     /* live entries (ctl, d->lock) */
	/* growth stats; inject_grow_fail is a test hook (fail that many
	 * allocations as if out of memory) */
	uint64_t            n_grow, n_grow_fail;
	uint32_t            inject_grow_fail;
	struct dp_spd      *spd;      /* published policy snapshot (see above) */
	uint64_t            n_spd_fail; /* snapshot rebuilds that failed (ENOMEM) */
	uint64_t            n_acl_build;  /* OUT classifier (re)builds */
	uint64_t            n_acl_reuse;  /* snapshots that kept the classifier */
	uint64_t            n_nh_unref;   /* next hops removed with their last SA/SP */
	uint64_t            sp_ver;       /* dp_sp_ent.ver source */
	uint16_t            out_mtu;      /* outer port MTU (0: unchecked) */
	int                 expire_fd;    /* eventfd (>0). 0 = unset: a zeroed
	                                   * test priv must not be written. */
	uint64_t            spd_dirty_tsc; /* last policy change (0: compacted) */
	int                 verbose;
	uint64_t            sa_gen;       /* last dp_sa.gen handed out */
	/* Egress ESP L2: per-peer next hop learned from IKE/ESP sent by a
	 * configured tunnel peer (dp_nh.c), and our own outer-port MAC.
	 * Shared by every lcore (dpdk_nh.h). */
	struct r2dp_nh_tab  nh;
	unsigned            nh_size;         /* --nh-size: initial (0 = default) */
	uint8_t             our_mac[6];      /* outer (peer) tap MAC */
	uint8_t             our_inner_mac[6]; /* inner (plaintext host) tap MAC */

	char                tap_if[IFNAMSIZ];
	volatile int        running;
	unsigned            nb_wk;        /* packet workers, 1..DP_MAX_WK */
	struct dp_wk        wk[DP_MAX_WK + 1]; /* [nb_wk] unused */
	/* Test hooks: cryptodev dequeue override and the drain spin bound
	 * (NULL / 0 = rte_cryptodev_dequeue_burst / DP_CRYPTO_SPIN_DEFAULT). */
	uint16_t (*cdeq)(uint8_t dev, uint16_t qp, struct rte_crypto_op **ops,
	    uint16_t n);
	/* Test hook: cryptodev enqueue override (NULL = enqueue_burst). */
	uint16_t (*cenq)(uint8_t dev, uint16_t qp, struct rte_crypto_op **ops,
	    uint16_t n);
	uint32_t            spin_max;
};

/* Slot i (< sa_cap / sp_cap).  Chunk pointers are written once, before
 * the release store of the cap (or of a snapshot built after it). */
static inline struct dp_sa *
sa_at(const struct dpdk_priv *d, uint32_t i)
{
	return &__atomic_load_n(&d->sa_chunk[i / DP_CHUNK], __ATOMIC_RELAXED)
	    [i % DP_CHUNK];
}

static inline struct dp_sp_ent *
sp_at(const struct dpdk_priv *d, uint32_t i)
{
	return &__atomic_load_n(&d->sp_chunk[i / DP_CHUNK], __ATOMIC_RELAXED)
	    [i % DP_CHUNK];
}

static inline uint32_t
sa_cap(const struct dpdk_priv *d)
{
	return __atomic_load_n(&d->sa_cap, __ATOMIC_ACQUIRE);
}

static inline uint32_t
sp_cap(const struct dpdk_priv *d)
{
	return __atomic_load_n(&d->sp_cap, __ATOMIC_ACQUIRE);
}

static inline struct rte_hash *
sad_load(const struct dpdk_priv *d)
{
	return __atomic_load_n(&d->sad, __ATOMIC_ACQUIRE);
}

/* Inbound SAD (ATOMICS A1, SADB S2): an r2dp-owned rte_hash keyed on the
 * first 8 bytes of rte_ipsec_sadv4_key -- (SPI host order, DIP raw wire
 * order) -- created lock-free (RW_CONCURRENCY_LF: readers never take a
 * lock, so a preempted control thread can never stall a worker) with the
 * extendable bucket table (an insert cannot fail on cuckoo collisions
 * below capacity).  Deleted key slots are reclaimed only after a QSBR
 * grace period (sa_slot_retire).  The value is &dp_sa.sess. */
#define DP_SAD_KEY_LEN 8
struct rte_hash *dp_sad_create(const char *name, uint32_t cap);
static inline void
dp_sad_destroy(struct rte_hash *h)
{
	rte_hash_free(h);
}

/* Same contract as rte_ipsec_sad_lookup: sa[i] = value or NULL; returns
 * the number of hits.  Lock-free and wait-free for the caller. */
static inline uint32_t
dp_sad_lookup(const struct rte_hash *h, const union rte_ipsec_sad_key *const k[],
    void *sa[], uint32_t n)
{
	uint32_t hits = 0;

	for (uint32_t b = 0; b < n; b += RTE_HASH_LOOKUP_BULK_MAX) {
		const void *kp[RTE_HASH_LOOKUP_BULK_MAX];
		uint32_t m = RTE_MIN(n - b, (uint32_t)RTE_HASH_LOOKUP_BULK_MAX);
		uint64_t hit = 0;

		for (uint32_t i = 0; i < m; i++)
			kp[i] = &k[b + i]->v4;
		if (rte_hash_lookup_bulk_data(h, kp, m, &hit, &sa[b]) < 0)
			hit = 0;
		for (uint32_t i = 0; i < m; i++)
			if (!(hit & (1ull << i)))
				sa[b + i] = NULL;
			else
				hits++;
	}
	return hits;
}

/* Worker owning a tunnel is chosen at install, not by a hash.  A hash
 * clumps (measured: flows collapsed onto a subset of workers) and it does
 * not match the RX queue a packet arrives on, so every frame was steered.
 * tun_owner() in dpdk_sad.c assigns a new tunnel to the least-loaded
 * worker and keeps both directions and every rekey on that worker. */

/* Reset worker slot `id` (counters, queues) for priv `d`. */
static inline void
dp_wk_init(struct dpdk_priv *d, unsigned id)
{
	struct dp_wk *w = &d->wk[id];

	memset(w, 0, sizeof(*w));
	w->d = d;
	w->id = id;
	w->txq = (uint16_t)id;
	w->cqp = (uint16_t)id;
	w->lcore = RTE_MAX_LCORE;
}

/* The inbound SAD stores &dp_sa.sess as its value, so a session handed back
 * from dp_sad_lookup is the sess member of a dp_sa; recover the owner
 * and add `n` to its byte counter (byte-lifetime accounting). */
static inline void
sa_bytes_add(struct dpdk_priv *d, struct rte_ipsec_session *ss, uint64_t n)
{
	uintptr_t off = offsetof(struct dp_sa, sess);
	struct dp_sa *ds = (struct dp_sa *)((uint8_t *)ss - off);
	/* sanity: the recovered pointer must be a live table slot */
	if (ds->idx < sa_cap(d) && sa_at(d, ds->idx) == ds && sa_live(ds))
		__atomic_fetch_add(&ds->bytes, n, __ATOMIC_RELAXED);
}

extern const char *const dp_drop_name[DR_NUM];

/* Hard lifetime reached: byte counter at the limit, or hard time passed.
 * `now` is unix seconds (0 skips the time check). */
static inline int
sa_time_dead(const struct dp_sa *ds, uint64_t now)
{
	uint64_t dl = __atomic_load_n(&ds->hard_deadline, __ATOMIC_RELAXED);
	return now && dl && now >= dl;
}
static inline int
sa_dead(const struct dp_sa *ds, uint64_t now)
{
	uint64_t h = __atomic_load_n(&ds->hard_bytes, __ATOMIC_RELAXED);
	if (sa_time_dead(ds, now))
		return 1;
	return h && __atomic_load_n(&ds->bytes, __ATOMIC_RELAXED) >= h;
}
/* 1 if `n` more forwarded bytes still sit strictly under the hard limit.
 * Reaching the limit is dead (sa_dead uses >=), so the crossing packet
 * is not forwarded. pending = bytes of this run not yet added. */
static inline int
sa_byte_room(const struct dp_sa *ds, uint64_t pending, uint64_t n)
{
	uint64_t h = __atomic_load_n(&ds->hard_bytes, __ATOMIC_RELAXED);
	uint64_t b = __atomic_load_n(&ds->bytes, __ATOMIC_RELAXED);
	if (!h)
		return 1;
	return b + pending + n < h;
}
void dp_expire_kick(struct dpdk_priv *d);
/* Snap the byte counter to the hard limit (so ctl's sa_bytes sees it)
 * and wake ctl once. Does not add `pending`; the caller commits that
 * first. */
static inline void
sa_mark_expired(struct dpdk_priv *d, struct dp_sa *ds)
{
	uint64_t h = __atomic_load_n(&ds->hard_bytes, __ATOMIC_RELAXED);
	uint64_t b = __atomic_load_n(&ds->bytes, __ATOMIC_RELAXED);
	if (h && b < h)
		__atomic_store_n(&ds->bytes, h, __ATOMIC_RELAXED);
	if (!__atomic_exchange_n(&ds->expire_kicked, 1, __ATOMIC_RELAXED))
		dp_expire_kick(d);
}
/* natt_class() results (dpdk_esp.c). */
enum { NT_NONE, NT_ESP, NT_IKE, NT_KEEPALIVE };

#define spd_rebuild(d) spd_rebuild_ex((d), 0)

/* dpdk_sad.c */
void
sa_slot_free(struct dpdk_priv *d, struct dp_sa *ds);
int dp_sa_grow(struct dpdk_priv *d);
int dp_sp_grow(struct dpdk_priv *d);
void dp_tables_free(struct dpdk_priv *d);
void
dpdk_caps(struct fwd_dp *dp);
int
sa_install(struct dpdk_priv *d, const struct r2dp_sa *rsa,
    const void *key, size_t keylen, int remove, int inbound);
int
dpd_sa_add(struct fwd_dp *dp, int add, const struct r2dp_sa *sa,
    const void *blob, size_t blen);
int64_t
dpd_sa_bytes(struct fwd_dp *dp, uint32_t spi, uint32_t dip);
int
dpd_sa_set_hard_bytes(struct fwd_dp *dp, uint32_t spi, uint32_t dip,
    uint64_t hard);
int
dpd_sa_set_hard_time(struct fwd_dp *dp, uint32_t spi, uint32_t dip,
    uint64_t deadline);
struct dp_sa *
sa_of_sess(struct dpdk_priv *d, struct rte_ipsec_session *ss);

/* dpdk_spd.c */
struct dp_sa *
sa_by_policy(struct dpdk_priv *d, const struct r2dp_sp *sp);
int
dpd_sp_add(struct fwd_dp *dp, struct r2dp_sp *sp);
int
dpd_sp_del(struct fwd_dp *dp, const struct r2dp_sp *sp);
int
inbound_policy_ok(struct dpdk_priv *d, const struct dp_sa *ds,
    const uint8_t *ip, size_t avail);
int
in_pol_fits(const struct r2dp_sp *sp, const struct dp_sa *ds);
int
spd_rebuild_ex(struct dpdk_priv *d, int policies_changed);
void
spd_teardown(struct dpdk_priv *d);
/* ctl idle hook: compact the OUT classifier once the policy set is quiet */
void
spd_idle(struct dpdk_priv *d);
const struct r2dp_sp *
sp_match_out(struct dpdk_priv *d, const struct rte_ipv4_hdr *ip, size_t avail,
    struct dp_sa **sa);
void
sp_match_out_burst(struct dpdk_priv *d, const struct rte_ipv4_hdr *const ip[],
    const size_t avail[], uint16_t n, const struct r2dp_sp *sp[],
    struct dp_sa *sa[]);
int
is_tunnel_peer(struct dpdk_priv *d, uint32_t ip);

/* dpdk_esp.c */
int
natt_class(const uint8_t *p, uint32_t len);
int
replay_accept(struct dp_sa *ds, uint32_t lo);
uint16_t
crypto_run(struct dp_wk *w, struct rte_ipsec_session *ss,
    struct rte_mbuf *mb[], uint16_t n, struct rte_mbuf *ok[]);
uint16_t
esp_inbound(struct dp_wk *w, struct rte_mbuf *bufs[], uint16_t nr,
    struct rte_mbuf *out[], uint16_t *nout);
int
in_inner_ok(struct dpdk_priv *d, struct rte_ipsec_session *ss,
    struct rte_mbuf *mb);
void
esp_outbound(struct dp_wk *w, struct rte_mbuf *bufs[], uint16_t nr,
    struct rte_mbuf *out[], uint16_t *nout, uint16_t *nbypass);

/* Returns how many frames resolved to an SA owned by a worker other
 * than `self` (ESP that arrived on the wrong queue, REPLAY R1). */
uint16_t
dp_steer_outer(struct dpdk_priv *d, struct rte_mbuf *m[], uint16_t n,
    uint8_t t[], unsigned self);
/* Reclaim a stuck device's late completions (worker; also polled while
 * idle).  Returns the ops it still holds. */
uint32_t
crypto_drain_stale(struct dp_wk *w);
/* Free retired SA slots whose sessions are no longer pinned (ctl, under
 * d->lock). */
void
sa_reap(struct dpdk_priv *d);

void
dp_steer_inner(struct dpdk_priv *d, struct rte_mbuf *m[], uint16_t n,
    uint8_t t[]);

/* dpdk_stats.c */
void
dpd_stats_sum(const struct dpdk_priv *d, struct dp_wk *t);
void
dpd_stats_dump(struct dpdk_priv *d, FILE *f);

#endif /* R2DP_DPDK_INT_H */

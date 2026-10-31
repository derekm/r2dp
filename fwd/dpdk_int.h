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
#include <rte_acl.h>
#include <rte_ring.h>
#include <rte_hash_crc.h>

#include "r2dp/client.h"
#include "dp.h"
#include "ctl.h"
#include "dp_gcm.h"
#include "dp_nh.h"
#include "dp_sel.h"
#include <signal.h>

#define MEMPOOL_CACHE 256
#define MEMPOOL_SIZE  16384
#define MAX_SA        FWD_MAXSA
#define DP_RING_SZ    1024  /* dispatcher -> worker ring, per direction */
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
	uint64_t           bytes;    /* total bytes crypted on this SA (soft/hard
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
	DR_CRYPTO_ENQ,      /* cryptodev queue full */
	DR_NOMEM,           /* op pool, headroom, output array */
	DR_NO_NEXTHOP,      /* egress ESP with no learned peer MAC */
	DR_CLEAR_OUTER,     /* non-IKE/ARP cleartext on the outer side */
	DR_ESP_ON_INNER,    /* ESP arriving on the plaintext side */
	DR_TX_FULL,         /* tx ring full */
	DR_CRYPTO_STUCK,    /* cryptodev stopped completing ops (see crypto_run) */
	DR_ENCAP,           /* ESP vs ESP-in-UDP framing does not match the SA */
	DR_STEER,           /* SA owned by another worker, or worker ring full */
	DR_NUM
};
#define DROP(w, r, n) do { uint64_t n_ = (n); (w)->n_drop += n_; \
	(w)->n_dropr[(r)] += n_; } while (0)

#define DP_MAX_WK 8       /* packet workers (-n); + 1 dispatcher slot */

struct dpdk_priv;

/* One packet worker (or, at index nb_wk, the dispatcher).  Everything here
 * is written by that lcore only; the stats dump sums the counters.  Each
 * worker has its own port TX queue and cryptodev queue pair, and in
 * multi-worker mode receives its packets on two SP/SC rings filled by the
 * dispatcher (see dp_dpdk.c). */
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
	uint64_t            n_crypto_stuck;  /* times the device stopped completing */
	uint64_t            n_natt_keepalive; /* RFC 3948 keepalives consumed */
} __rte_cache_aligned;

#define PEER_HSZ 4096     /* power of two, > 2 * (2 * MAX_SA) */

struct dp_pol {
	const struct r2dp_sp *sp;
	int32_t  sa_idx;          /* bound EGRESS SA slot, -1 = none */
	uint64_t sa_gen;          /* that slot's gen at bind time */
	int      score;           /* r2dp_sel_score(sp) */
	int      slot;            /* sp_tab slot (tie-break) */
};

struct dp_spd {
	uint32_t       nout;
	struct dp_pol *out;       /* OUT policies, most specific first */
	struct rte_acl_ctx *acl;  /* OUT classifier over out[] (NULL: none) */
	/* Inbound (RFC 4301 s5.2) check, indexed by SA slot: the IN/FWD PROTECT
	 * policies whose tunnel endpoints/reqid fit that SA are
	 * in_pol[in_off[slot] .. in_off[slot+1]), valid while the slot's gen
	 * still equals in_gen[slot] (else the worker falls back to a scan). */
	uint32_t      *in_off;              /* MAX_SA + 1 */
	uint64_t      *in_gen;              /* MAX_SA */
	const struct r2dp_sp **in_pol;
	/* Tunnel peers (far ends of SAs and PROTECT policies), open addressing,
	 * 0 = empty; peer_zero records 0.0.0.0 itself. */
	uint32_t       peer[PEER_HSZ];
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
	struct rte_mempool *sess_mp;   /* crypto session mempool */
	struct rte_mempool *cop_mp;    /* crypto operation mempool */
	struct rte_ipsec_sad *sad;
	struct rte_cryptodev_info cdev_info;
	uint8_t             cdev_id;
	int                 have_cdev;
	rte_spinlock_t      lock;
	struct rte_rcu_qsbr *rcu;   /* H5: QSBR for the ctl<->worker SA/SP handoff */
	unsigned            rcu_tid; /* worker thread id registered with the QSBR */
	struct dp_sa        sa_tab[MAX_SA];
	struct dp_sp_ent    sp_tab[MAX_SA];
	struct dp_spd      *spd;      /* published policy snapshot (see above) */
	uint64_t            n_spd_fail; /* snapshot rebuilds that failed (ENOMEM) */
	int                 verbose;
	uint64_t            sa_gen;       /* last dp_sa.gen handed out */
	/* Egress ESP L2: per-peer next hop learned from IKE/ESP sent by a
	 * configured tunnel peer (dp_nh.c), and our own outer-port MAC.
	 * Worker-thread only. */
	struct r2dp_nh_tab  nh;
	uint8_t             our_mac[6];      /* outer (peer) tap MAC */
	uint8_t             our_inner_mac[6]; /* inner (plaintext host) tap MAC */

	char                tap_if[IFNAMSIZ];
	volatile int        running;
	unsigned            nb_wk;        /* packet workers, 1..DP_MAX_WK */
	struct dp_wk        wk[DP_MAX_WK + 1]; /* [nb_wk] = dispatcher */
	/* Test hooks: cryptodev dequeue override and the drain spin bound
	 * (NULL / 0 = rte_cryptodev_dequeue_burst / DP_CRYPTO_SPIN_DEFAULT). */
	uint16_t (*cdeq)(uint8_t dev, uint16_t qp, struct rte_crypto_op **ops,
	    uint16_t n);
	uint32_t            spin_max;
};

/* Worker owning a tunnel's SAs: a hash of its two endpoints (raw wire
 * order), order-independent so both directions and every rekey of the
 * tunnel stay on one worker -- no state hand-over, no reordering. */
static inline uint8_t
dp_owner(unsigned nb_wk, uint32_t a, uint32_t b)
{
	uint32_t lo = a < b ? a : b, hi = a < b ? b : a;

	if (nb_wk <= 1)
		return 0;
	return (uint8_t)(rte_hash_crc_4byte(hi, rte_hash_crc_4byte(lo, 0))
	    % nb_wk);
}

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
 * from rte_ipsec_sad_lookup is the sess member of a dp_sa; recover the owner
 * and add `n` to its byte counter (byte-lifetime accounting). */
static inline void
sa_bytes_add(struct dpdk_priv *d, struct rte_ipsec_session *ss, uint64_t n)
{
	uintptr_t off = offsetof(struct dp_sa, sess);
	struct dp_sa *ds = (struct dp_sa *)((uint8_t *)ss - off);
	/* sanity: the recovered pointer must land inside sa_tab */
	uintptr_t base = (uintptr_t)d->sa_tab, end = base + sizeof(d->sa_tab);
	if ((uintptr_t)ds >= base && (uintptr_t)ds < end && sa_live(ds))
		__atomic_fetch_add(&ds->bytes, n, __ATOMIC_RELAXED);
}

extern const char *const dp_drop_name[DR_NUM];
/* natt_class() results (dpdk_esp.c). */
enum { NT_NONE, NT_ESP, NT_IKE, NT_KEEPALIVE };

#define spd_rebuild(d) spd_rebuild_ex((d), 0)

/* dpdk_sad.c */
void
sa_slot_free(struct dpdk_priv *d, struct dp_sa *ds);
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
const struct r2dp_sp *
sp_match_out(struct dpdk_priv *d, const struct rte_ipv4_hdr *ip, size_t avail,
    struct dp_sa **sa);
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

/* dpdk_stats.c */
void
dpd_stats_sum(const struct dpdk_priv *d, struct dp_wk *t);
void
dpd_stats_dump(struct dpdk_priv *d, FILE *f);

#endif /* R2DP_DPDK_INT_H */

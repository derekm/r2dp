/*
 * fwd/dp_dpdk.c -- M1 DPDK dataplane for the r2dp forwarder.
 *
 * Implements the fwd_dp vtable (dp.h) on DPDK 24.11:
 *   - SAD:  rte_ipsec_sad (SPI_DIP key, RW-concurrency) storing a
 *           struct rte_ipsec_sa per installed SA -- the SAD the worker's
 *           ESP lookups resolve against.
 *   - SPD:  the in-process policy copy in ctl.c is authoritative at M1;
 *           the rte_acl classifier lands with the worker loop.
 *
 * Only compiled when -Denable_dpdk is on (meson gates it).
 *
 * MT: control thread (r2dp socket) installs SAs; a worker looks them up.
 * rte_ipsec_sad RW-concurrency allows add/del beside lookups; a spinlock
 * guards the SA slot bitmap.
 *
 * SCOPE: this provides the SAD dataplane + the control-plane install path
 * (the SA-install seam of the M1 exit gate).  The remaining packet path --
 * run-to-completion worker loop, librte_ipsec crypto sessions on the
 * crypto_openssl device, and the net_tap exception/ingress port -- is the
 * next piece and consumes this SAD.
 */
#ifdef R2DP_HAVE_DPDK

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

#include "r2dp/client.h"
#include "dp.h"
#include "ctl.h"
#include "dp_gcm.h"
#include "dp_nh.h"
#include "dp_sel.h"

#define MEMPOOL_CACHE 256
#define MEMPOOL_SIZE  16384
#define MAX_SA        FWD_MAXSA
#define BURST_SZ      128
#define TAP_IF_DEFAULT "r2dp-tap"

#define RP_BITS  256              /* >= the largest window (wsize is a u8) */
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
	uint32_t           rp_w;     /* window size (packets), 1..RP_BITS */
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
	DR_CRYPTO_ENQ,      /* cryptodev queue full / stuck */
	DR_NOMEM,           /* op pool, headroom, output array */
	DR_NO_NEXTHOP,      /* egress ESP with no learned peer MAC */
	DR_CLEAR_OUTER,     /* non-IKE/ARP cleartext on the outer side */
	DR_ESP_ON_INNER,    /* ESP arriving on the plaintext side */
	DR_TX_FULL,         /* tx ring full */
	DR_NUM
};
static const char *const dp_drop_name[DR_NUM] = {
	"malformed", "no_sa_in", "no_sa_out", "policy_discard", "inner_sel",
	"crypto_fail", "replay", "ipsec_reject", "crypto_enq", "nomem", "no_nexthop",
	"clear_outer", "esp_on_inner", "tx_full",
};
#define DROP(w, r, n) do { uint64_t n_ = (n); (w)->n_drop += n_; \
	(w)->n_dropr[(r)] += n_; } while (0)

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
	const char          *cdev_name_sel; /* PMD actually selected (diagnostics) */
	int                 have_cdev;
	/* N workers (M3): one run-to-completion lcore each, own RX/TX queue and
	 * own crypto queue pair and own counters.  SAD/SPD/sa_tab/sp_tab/spd are
	 * SHARED read-mostly across workers (QSBR-protected handoff from ctl).
	 * nb workers / queues set up in fwd_dp_dpdk_probe. */
	uint16_t            nworkers;
	struct dp_worker    *w;        /* array [nworkers] */
	rte_spinlock_t      lock;
	struct rte_rcu_qsbr *rcu;   /* H5: QSBR for the ctl<->worker SA/SP handoff */
	struct dp_sa        sa_tab[MAX_SA];
	struct dp_sp_ent    sp_tab[MAX_SA];
	struct dp_spd      *spd;      /* published policy snapshot (see above) */
	uint64_t            n_spd_fail; /* snapshot rebuilds that failed (ENOMEM) */
	int                 verbose;
	uint64_t            sa_gen;       /* last dp_sa.gen handed out */
	char                tap_if[IFNAMSIZ];
	volatile int        running;
};

/* Per-worker state (M3).  Own copy of everything the run-to-completion loop
 * touches so workers never contend on a shared counter or a shared next-hop
 * table (which is peer-keyed and may be relearned mid-flight by a different
 * lcore's MAC learning). */
struct dp_worker {
	struct dpdk_priv *d;       /* shared priv (SAD/SPD/pools) */
	unsigned            lcore;
	uint16_t            qid;        /* rx/tx queue on both ports */
	uint16_t            cqp;        /* cryptodev queue pair */
	struct r2dp_nh_tab  nh;         /* per-worker next-hop table */
	uint8_t             our_mac[6];      /* outer (peer) tap MAC */
	uint8_t             our_inner_mac[6]; /* inner (plaintext host) tap MAC */
	uint64_t            n_rx, n_tx, n_esp, n_ike, n_drop;
	uint64_t            n_dropr[DR_NUM]; /* n_drop split by reason */
};

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

/* ------------------------------------------------------------------ */
static void
dpdk_caps(struct fwd_dp *dp)
{
	uint32_t *enc_caps = dp->caps_bits_enc;
	uint32_t *integ_caps = dp->caps_bits_integ;

	memset(enc_caps, 0, sizeof(enc_caps[0]) * R2DP_CAP_WORDS);
	memset(integ_caps, 0, sizeof(integ_caps[0]) * R2DP_CAP_WORDS);
	/* Advertise only the AES-GCM-16 tunnel transform dp_sa_init actually
	 * implements.  AES-CBC was listed but is refused (dp_sa_init only
	 * accepts AES_GCM_16); advertising it would make racoon2 negotiate
	 * something the dataplane cannot install. */
	enc_caps[0] = (1u << R2DP_ENCR_AES_GCM_16);
	/* AEAD transforms carry their auth inside; the INTEG side is NONE. */
	integ_caps[0] = (1u << R2DP_INTEG_NONE);
}

static int
addr4_to_u32(const struct r2dp_addr *a, uint32_t *out)
{
	if (a->family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;
	memcpy(out, a->addr, 4);
	return 0;
}

/* r2dp SA -> rte_ipsec_sa + crypto session + ipsec session.  M1: AES-GCM-16
 * tunnel.  AEAD key blob = cipher key (16) || salt (4) = 20 bytes (M0 f3).
 * `inbound` distinguishes an SA protecting traffic TO us (our GETSPI: install
 * in the inbound SAD, INGRESS+DECRYPT) from the peer's (EGRESS+ENCRYPT for
 * the egress leg, not yet in the SAD). */
static int
dp_sa_init(struct dpdk_priv *d, struct dp_sa *ds, const struct r2dp_sa *rsa,
    const void *key, size_t keylen, int inbound)
{
	struct rte_ipsec_sa_prm prm;
	struct rte_crypto_sym_xform aead;
	struct rte_ipv4_hdr eh;   /* prm.tun.hdr points here: outlives init below */
	size_t sa_sz;
	int ret;

	/* The blob handed over must be exactly what the SA header claims:
	 * enckeylen (cipher key || salt) followed by authkeylen. */
	if (key == NULL || keylen != (size_t)rsa->enckeylen + rsa->authkeylen)
		return -EINVAL;
	if (!d->have_cdev)
		return -ENODEV;
	/* D10: refuse what the data plane cannot honour, instead of accepting
	 * and silently misbehaving.  M1 is IPv4 AES-GCM tunnel; NAT-T (ESP-in-UDP
	 * 4500) is now handled by the outer-tap demux (uf1), so a NAT-T SA is
	 * acceptable -- its ESP decrypts the same way after the encap is stripped. */
	if (rsa->natt_type != R2DP_NATT_NONE &&
	    rsa->natt_type != R2DP_NATT_ESPINUDP)
		return -EOPNOTSUPP;              /* unknown NAT-T encapsulation */
	if (rsa->src.family != R2DP_AF_INET4 ||
	    rsa->dst.family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;           /* IPv4 only */
	if (rsa->mode != R2DP_MODE_TUNNEL)
		return -EOPNOTSUPP;             /* tunnel mode only */
	ret = r2dp_gcm_sa_prm(rsa, key, inbound, &prm, &aead, &eh);
	if (ret < 0)
		return ret;

	/* Size the SA from the *filled* prm (rte_ipsec_sa_size(NULL) returns
	 * -EINVAL, i.e. -22).  Mirrors ipsec-secgw/sa.c ipsec_sa_init. */
	sa_sz = rte_ipsec_sa_size(&prm);
	if ((int)sa_sz < 0)
		return -EINVAL;
	ds->sa = rte_zmalloc(NULL, sa_sz, RTE_CACHE_LINE_SIZE);
	if (!ds->sa)
		return -ENOMEM;

	if (rte_ipsec_sa_init(ds->sa, &prm, sa_sz) < 0) {
		rte_free(ds->sa);
		ds->sa = NULL;
		return -EINVAL;
	}

	/* crypto session on the openssl device */
	ds->cses = rte_cryptodev_sym_session_create(d->cdev_id, &aead, d->sess_mp);
	if (!ds->cses) {
		rte_ipsec_sa_fini(ds->sa);
		rte_free(ds->sa);
		ds->sa = NULL;
		return -ENOMEM;
	}

	/* bind it into an rte_ipsec_session.  We drive the ASYNC cryptodev path
	 * (rte_ipsec_pkt_crypto_prepare + enqueue/dequeue on the OpenSSL device),
	 * which librte_ipsec keys off RTE_SECURITY_ACTION_TYPE_NONE.  CPU_CRYPTO
	 * would select the SYNC prepare (rte_ipsec_pkt_cpu_prepare) instead, so
	 * the async call would hit the wrong function -- a crash on the first
	 * decrypted packet. */
	memset(&ds->sess, 0, sizeof(ds->sess));
	ds->sess.sa = ds->sa;
	ds->sess.type = RTE_SECURITY_ACTION_TYPE_NONE;
	ds->sess.crypto.ses = ds->cses;
	ds->sess.crypto.dev_id = d->cdev_id;
	if (rte_ipsec_session_prepare(&ds->sess) < 0) {
		rte_cryptodev_sym_session_free(d->cdev_id, ds->cses);
		rte_ipsec_sa_fini(ds->sa);
		rte_free(ds->sa);
		ds->sa = NULL; ds->cses = NULL;
		return -EINVAL;
	}

	ds->spi = ntohl(rsa->spi);
	ds->proto = rsa->proto;
	ds->rp_top = 0;
	memset(ds->rp_map, 0, sizeof(ds->rp_map));
	ds->rp_w = rsa->wsize ? rsa->wsize : 64;     /* as r2dp_gcm_sa_prm */
	ds->rp_esn = (rsa->saflags & R2DP_SAF_ESN) != 0;
	/* tunnel endpoints: addr4_to_u32 memcpy's rsa->dst.addr[0..4], raw wire
	 * order; match that exactly for endpoint selection (H3). */
	memcpy(&ds->dsta, &rsa->dst.addr[0], 4);
	memcpy(&ds->srca, &rsa->src.addr[0], 4);
	ds->used = 1;
	return 0;
}

static int spd_rebuild_ex(struct dpdk_priv *d, int policies_changed);
#define spd_rebuild(d) spd_rebuild_ex((d), 0)
static int in_pol_fits(const struct r2dp_sp *sp, const struct dp_sa *ds);

/* Tear down one slot: free the crypto session, ipsec SA, and zero it.
 * Caller holds d->lock. */
static void
sa_slot_free(struct dpdk_priv *d, struct dp_sa *ds)
{
	if (ds->cses)
		rte_cryptodev_sym_session_free(d->cdev_id, ds->cses);
	if (ds->sa)
		rte_ipsec_sa_fini(ds->sa);
	rte_free(ds->sa);
	memset(ds, 0, sizeof(*ds));
}

/* H5: retire a slot the worker may currently be using.  Step 1 (unlink):
 * clear `used` under the lock so SA/SP lookups stop returning this session,
 * and drop it from the inbound SAD.  Step 2: wait for the worker to pass a
 * grace period (it reports quiescent after each loop, i.e. after its crypto
 * path has finished touching every session it grabbed this iteration).  Only
 * then free the session memory -- this is what prevents the ctl<->worker
 * use-after-free on SA_DEL / rekey under traffic.  Caller holds d->lock. */
static void
sa_slot_retire(struct dpdk_priv *d, struct dp_sa *ds)
{
	union rte_ipsec_sad_key keyv;
	int inbound = ds->inbound;

	__atomic_store_n(&ds->used, 0, __ATOMIC_RELEASE); /* unlink from worker */
	if (inbound) {
		memset(&keyv, 0, sizeof(keyv));
		keyv.v4.spi = ds->spi;
		keyv.v4.dip = ds->dip;
		rte_ipsec_sad_del(d->sad, &keyv, RTE_IPSEC_SAD_SPI_DIP);
	}
	if (d->rcu)
		rte_rcu_qsbr_synchronize(d->rcu, RTE_QSBR_THRID_INVALID);
	sa_slot_free(d, ds);
}

/* ------------------------------------------------------------------ */
static int
sa_install(struct dpdk_priv *d, const struct r2dp_sa *rsa,
    const void *key, size_t keylen, int remove, int inbound)
{
	union rte_ipsec_sad_key keyv;
	uint32_t dip = 0;
	int idx = -1, ret;

	if (addr4_to_u32(&rsa->dst, &dip) < 0)
		return -EAFNOSUPPORT;

	rte_spinlock_lock(&d->lock);

	if (remove) {
		for (int i = 0; i < MAX_SA; i++) {
			if (d->sa_tab[i].used &&
			    d->sa_tab[i].spi == ntohl(rsa->spi) &&
			    d->sa_tab[i].proto == rsa->proto &&
			    d->sa_tab[i].dip == dip) {
				sa_slot_retire(d, &d->sa_tab[i]);
				(void)spd_rebuild(d);  /* rebind to a remaining SA */
				break;
			}
		}
		rte_spinlock_unlock(&d->lock);
		return 0;
	}

	/* Upsert (SA_ADD on a larval, or SA_UPDATE on a live SA): the SAD key is
	 * (SPI, DIP), so installing a new session for the same SPI requires a
	 * del-then-add.  Find the slot holding that SPI+DIP's current session.
	 * The match and the del must use the SAME (SPI, DIP) key; SPIs are only
	 * unique per destination, so matching on SPI+proto alone could tear down
	 * another peer's SA. */
	idx = -1;
	for (int i = 0; i < MAX_SA; i++) {
		if (d->sa_tab[i].used && d->sa_tab[i].proto == rsa->proto &&
		    d->sa_tab[i].spi == ntohl(rsa->spi) &&
		    d->sa_tab[i].dip == dip) {
			idx = i;
			break;
		}
	}

	/* M2 (build-then-swap): build the NEW session first so a failure leaves
	 * the old SA untouched (ctl still holds the old one as last-known-good).
	 * Only after the new session exists do we tear the old one down and
	 * publish the new one -- no window where the dataplane has nothing. */
	int newidx = -1;
	for (int i = 0; i < MAX_SA; i++)
		if (!d->sa_tab[i].used) { newidx = i; break; }
	if (newidx < 0) {
		rte_spinlock_unlock(&d->lock);
		return -ENOSPC;
	}
	{
		struct dp_sa scratch;
		memset(&scratch, 0, sizeof(scratch));
		ret = dp_sa_init(d, &scratch, rsa, key, keylen, inbound);
		if (ret < 0) {
			rte_spinlock_unlock(&d->lock);
			return ret;
		}
		/* dp_sa_init marks scratch used; publish only after every
		 * field below is written (release store), never via this copy */
		scratch.used = 0;
		d->sa_tab[newidx] = scratch;
	}
	d->sa_tab[newidx].spi = ntohl(rsa->spi);
	d->sa_tab[newidx].proto = rsa->proto;
	d->sa_tab[newidx].reqid = rsa->reqid;
	d->sa_tab[newidx].dip = dip;
	d->sa_tab[newidx].inbound = inbound;
	d->sa_tab[newidx].natt = rsa->natt_type;
	d->sa_tab[newidx].gen = ++d->sa_gen;
	/* publish last: the worker only proceeds past `used` == 1 */
	__atomic_store_n(&d->sa_tab[newidx].used, 1, __ATOMIC_RELEASE);

	/* Rebind policies before retiring the old session: a rekey switches
	 * egress to the newest SA with no window where the policy has none.
	 * A failed rebuild leaves the previous snapshot, whose bindings the
	 * worker re-validates by generation (stale => drop, never misuse). */
	(void)spd_rebuild(d);

	/* tear down the old same-SPI session (now that a replacement exists) */
	if (idx >= 0)
		sa_slot_retire(d, &d->sa_tab[idx]);

	/* Only inbound SAs (protecting traffic TO us) belong in the (SPI,DIP)
	 * inbound SAD; outbound SAs stay in sa_tab for the SPD-driven egress
	 * leg.  The SAD is consulted only by the inbound worker. */
	if (!inbound) {
		rte_spinlock_unlock(&d->lock);
		return 0;
	}

	memset(&keyv, 0, sizeof(keyv));
	keyv.v4.spi = ntohl(rsa->spi);
	keyv.v4.dip = dip;
	if (d->verbose) {
		fprintf(stderr,
		    "r2dp-fwd: SA_ADD key spi=%08x dip=%08x (rsa.spi=%08x raw dip=%08x)\n",
		    ntohl(rsa->spi), dip, rsa->spi, dip);
	}
	ret = rte_ipsec_sad_add(d->sad, &keyv, RTE_IPSEC_SAD_SPI_DIP,
	    &d->sa_tab[newidx].sess);   /* SAD value = the ipsec session ptr */
	if (ret < 0) {
		if (d->sa_tab[newidx].cses)
			rte_cryptodev_sym_session_free(d->cdev_id, d->sa_tab[newidx].cses);
		if (d->sa_tab[newidx].sa)
			rte_ipsec_sa_fini(d->sa_tab[newidx].sa);
		rte_free(d->sa_tab[newidx].sa);
		memset(&d->sa_tab[newidx], 0, sizeof(d->sa_tab[newidx]));
		rte_spinlock_unlock(&d->lock);
		return ret;
	}
	/* .inbound/.dip were already set on sa_tab[newidx] at publish (above);
	 * never touch sa_tab[idx] here -- idx is -1 for a fresh install, so
	 * indexing it would write before the array (OOB).  The worker reads
	 * these fields off newidx via the SAD-returned session. */
	rte_spinlock_unlock(&d->lock);
	return 0;
}

/* ------------------------------------------------------------------ */
static inline int
dpd_sa_add(struct fwd_dp *dp, int add, const struct r2dp_sa *sa,
    const void *blob, size_t blen)
{
	struct dpdk_priv *d = dp->priv;

	return sa_install(d, sa, blob, blen, !(add & 1),
	    (add & FWD_DP_SA_INBOUND) != 0);
}

static int
dpd_sp_add(struct fwd_dp *dp, struct r2dp_sp *sp)
{
	struct dpdk_priv *d = dp->priv;
	struct r2dp_sp *nsp, *old;
	int slot = -1;

	if (!sp->slid)
		return -EINVAL;
	nsp = malloc(sizeof(*nsp));
	if (!nsp)
		return -ENOMEM;
	*nsp = *sp;                 /* fully built before it is published */
	rte_spinlock_lock(&d->lock);
	for (int i = 0; i < MAX_SA; i++) {
		if (d->sp_tab[i].sp) {
			if (d->sp_tab[i].sp->slid == sp->slid) { slot = i; break; }
		} else if (slot < 0)
			slot = i;
	}
	if (slot < 0) {
		rte_spinlock_unlock(&d->lock);
		free(nsp);
		return -ENOSPC;
	}
	old = d->sp_tab[slot].sp;
	__atomic_store_n(&d->sp_tab[slot].sp, nsp, __ATOMIC_RELEASE);
	if (spd_rebuild_ex(d, 1) < 0) {
		/* the worker keeps enforcing the previous snapshot; put the
		 * table back so control state and dataplane agree */
		__atomic_store_n(&d->sp_tab[slot].sp, old, __ATOMIC_RELEASE);
		if (d->rcu)
			rte_rcu_qsbr_synchronize(d->rcu, RTE_QSBR_THRID_INVALID);
		rte_spinlock_unlock(&d->lock);
		free(nsp);
		return -ENOMEM;
	}
	if (old) {
		/* spd_rebuild waited a grace period after publishing the
		 * snapshot that no longer references `old`; the direct sp_tab
		 * readers are covered by the same wait */
		free(old);
	}
	rte_spinlock_unlock(&d->lock);
	return 0;
}

static int
dpd_sp_del(struct fwd_dp *dp, const struct r2dp_sp *sp)
{
	struct dpdk_priv *d = dp->priv;
	struct r2dp_sp *old = NULL;

	rte_spinlock_lock(&d->lock);
	for (int i = 0; i < MAX_SA; i++) {
		if (d->sp_tab[i].sp && d->sp_tab[i].sp->slid == sp->slid) {
			old = d->sp_tab[i].sp;
			__atomic_store_n(&d->sp_tab[i].sp, NULL, __ATOMIC_RELEASE);
			if (spd_rebuild_ex(d, 1) < 0) {
				/* keep enforcing the old (stricter or equal)
				 * policy rather than dropping it unseen */
				__atomic_store_n(&d->sp_tab[i].sp, old,
				    __ATOMIC_RELEASE);
				rte_spinlock_unlock(&d->lock);
				return -ENOMEM;
			}
			break;
		}
	}
	if (old)
		free(old);   /* spd_rebuild already waited a grace period */
	rte_spinlock_unlock(&d->lock);
	return 0;
}

/* dataplane vtable (process-static so it outlives the probe).  Not const:
 * the .caps callback fills dp->ops->caps_bits_* in place. */
static int64_t
dpd_sa_bytes(struct fwd_dp *dp, uint32_t spi, uint32_t dip)
{
	struct dpdk_priv *d = dp->priv;
	int64_t v = -1;
	rte_spinlock_lock(&d->lock);
	for (int i = 0; i < MAX_SA; i++)
		if (d->sa_tab[i].used && d->sa_tab[i].spi == spi &&
		    d->sa_tab[i].dip == dip) {
			v = (int64_t)__atomic_load_n(&d->sa_tab[i].bytes,
			    __ATOMIC_RELAXED);
			break;
		}
	rte_spinlock_unlock(&d->lock);
	return v;
}

static struct fwd_dp_ops dpdk_ops;

/* ------------------------------------------------------------------ */
/* M1 packet path: run-to-completion on one lcore.  rx from the tap port,
 * classify, and tx back (the M1 topology is a TAP bridged to a kernel
 * interface; ESP is later processed, non-ESP IKE/ARP rides the exception
 * path -- both re-emit on the same port so the kernel sees them). */
static int
port_init(struct dpdk_priv *d, uint16_t port, uint16_t nq)
{
	struct rte_eth_conf conf;
	struct rte_eth_dev_info dev_info;

	if (port >= RTE_MAX_ETHPORTS)
		return -1;
	memset(&conf, 0, sizeof(conf));
	if (rte_eth_dev_info_get(port, &dev_info) < 0) {
		fprintf(stderr, "r2dp-fwd: dev_info_get(port %u) failed\n", port);
		return -1;
	}
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* M3: one RX/TX queue per worker (worker i polls queue i). */
	uint16_t nrxq = nq, ntxq = nq;
	if (rte_eth_dev_configure(port, nrxq, ntxq, &conf) < 0)
		return -rte_errno;
	for (uint16_t q = 0; q < nrxq; q++)
		if (rte_eth_rx_queue_setup(port, q, 1024, rte_eth_dev_socket_id(port),
		    NULL, d->pool) < 0)
			return -rte_errno;
	for (uint16_t q = 0; q < ntxq; q++)
		if (rte_eth_tx_queue_setup(port, q, 1024, rte_eth_dev_socket_id(port),
		    NULL) < 0)
			return -rte_errno;
	if (rte_eth_dev_start(port) < 0)
		return -rte_errno;
	rte_eth_promiscuous_enable(port);
	return 0;
}

/* Inbound ESP: SAD-lookup by (SPI, DIP), run AES-GCM decrypt through the
 * OpenSSL cryptodev, then finalize with rte_ipsec_pkt_process.  One
 * enqueue/dequeue round per matched packet on the same lcore.  Decrypted
 * inner packets are written into `out` (up to *nout); unmatched/undecryptable
 * packets are freed.  Returns the number of mbufs consumed from `in`. */
static int in_inner_ok(struct dpdk_priv *d, struct rte_ipsec_session *ss,
    struct rte_mbuf *mb);
static struct dp_sa *sa_of_sess(struct dpdk_priv *d, struct rte_ipsec_session *ss);

/* RFC 4303 s3.4.3 / App. A anti-replay on an authenticated packet's 32-bit
 * sequence number: 1 = accept (and record), 0 = replay / too old. */
static int
replay_accept(struct dp_sa *ds, uint32_t lo)
{
	uint64_t t = ds->rp_top, sqn = lo;
	uint32_t w = ds->rp_w, tl = (uint32_t)t;

	if (ds->rp_esn) {                /* RFC 4303 App. A2.2 reconstruction */
		uint64_t hi = t >> 32;
		if (tl >= w - 1) {
			if (lo < tl - w + 1) hi++;
		} else if (lo >= tl - w + 1 && hi) {
			hi--;
		}
		sqn = (hi << 32) | lo;
	}
	if (sqn == 0)
		return 0;
	if (sqn > t) {                   /* advance: clear the slots passed over */
		uint64_t d = sqn - t;
		if (d >= RP_BITS)
			memset(ds->rp_map, 0, sizeof(ds->rp_map));
		else
			for (uint64_t s = t + 1; s <= sqn; s++)
				ds->rp_map[(s % RP_BITS) / 64] &= ~(1ull << (s % 64));
		ds->rp_top = sqn;
	} else if (t - sqn >= w) {
		return 0;                    /* left of the window */
	} else if (ds->rp_map[(sqn % RP_BITS) / 64] & (1ull << (sqn % 64))) {
		return 0;                    /* seen */
	}
	ds->rp_map[(sqn % RP_BITS) / 64] |= 1ull << (sqn % 64);
	return 1;
}

/* Run n packets of ONE SA through lookaside crypto as a batch:
 * bulk op alloc -> rte_ipsec prepare -> enqueue -> dequeue (all of it) ->
 * per-op status check -> rte_ipsec process.  Every mbuf in mb[] is consumed:
 * the successfully processed ones are returned in ok[] (count returned),
 * every other one is dropped (counted, freed).  A failed op (AUTH_FAILED on
 * a forged ICV, any error) never reaches rte_ipsec_pkt_process, which does
 * not inspect op status (fail closed). */
static uint16_t
crypto_run(struct dp_worker *w, struct rte_ipsec_session *ss,
    struct rte_mbuf *mb[], uint16_t n, struct rte_mbuf *ok[])
{
	struct dpdk_priv *d = w->d;
	struct rte_crypto_op *cop[BURST_SZ];
	uint16_t k, enq, dq = 0, ng = 0, proc;
	unsigned rounds = 0;
	int rp = !(rte_ipsec_sa_type(ss->sa) & RTE_IPSEC_SATP_DIR_MASK);  /* inbound */
	struct dp_sa *ds;

	if (rte_crypto_op_bulk_alloc(d->cop_mp, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
	    cop, n) == 0) {
		for (uint16_t i = 0; i < n; i++) {
			DROP(w, DR_NOMEM, 1);
			rte_pktmbuf_free(mb[i]);
		}
		return 0;
	}
	for (uint16_t i = 0; i < n; i++)
		rte_crypto_op_attach_sym_session(cop[i], ss->crypto.ses);
	/* prepare moves the mbufs it rejected to the tail */
	k = rte_ipsec_pkt_crypto_prepare(ss, mb, cop, n);
	for (uint16_t i = k; i < n; i++) {
		DROP(w, DR_IPSEC_REJECT, 1);
		rte_pktmbuf_free(mb[i]);
	}
	enq = k ? rte_cryptodev_enqueue_burst(d->cdev_id, w->cqp, cop, k) : 0;
	for (uint16_t i = enq; i < k; i++) {
		DROP(w, DR_CRYPTO_ENQ, 1);
		rte_pktmbuf_free(mb[i]);
	}
	if (enq < n)
		rte_mempool_put_bulk(d->cop_mp, (void **)&cop[enq], n - enq);
	/* M3 (async crypto): do NOT busy-spin here waiting for the device --
	 * that synchronous spin pegged one core at 99.5% while 11 sat idle.
	 * A CPU-crypto PMD (aesni_mb / openssl) completes enqueued ops
	 * synchronously in this same lcore, so a short NON-BLOCKING dequeue
	 * pass reaps them all (usually on the first call).  Keep it bounded:
	 * anything still outstanding after the bound was not completed and is
	 * abandoned (counted DR_CRYPTO_ENQ below) -- never half-processed, so
	 * a torn mbuf is never forwarded and no op is double-reaped. */
	while (dq < enq && rounds < 4) {
		uint16_t got = rte_cryptodev_dequeue_burst(d->cdev_id, w->cqp,
		    &cop[dq], enq - dq);
		dq += got;
		rounds++;
	}
	ds = rp ? sa_of_sess(d, ss) : NULL;
	for (uint16_t i = 0; i < dq; i++) {
		struct rte_mbuf *m = cop[i]->sym->m_src;
		if (cop[i]->status == RTE_CRYPTO_OP_STATUS_SUCCESS) {
			if (ds) {
				/* authenticated: now the sequence number counts */
				const struct rte_esp_hdr *eh = rte_pktmbuf_mtod_offset(
				    m, const struct rte_esp_hdr *, m->l2_len + m->l3_len);
				if (!replay_accept(ds, rte_be_to_cpu_32(eh->seq))) {
					DROP(w, DR_REPLAY, 1);
					rte_pktmbuf_free(m);
					continue;
				}
			}
			ok[ng++] = m;
		} else {
			DROP(w, DR_CRYPTO_FAIL, 1);
			rte_pktmbuf_free(m);
		}
	}
	if (dq)
		rte_mempool_put_bulk(d->cop_mp, (void **)cop, dq);
	DROP(w, DR_CRYPTO_ENQ, enq - dq);       /* abandoned in a stuck device */
	if (!ng)
		return 0;
	/* process moves the mbufs it rejected (e.g. replay) to the tail */
	proc = rte_ipsec_pkt_process(ss, ok, ng);
	for (uint16_t i = proc; i < ng; i++) {
		DROP(w, DR_IPSEC_REJECT, 1);
		rte_pktmbuf_free(ok[i]);
	}
	return proc;
}

static uint16_t
esp_inbound(struct dp_worker *w, struct rte_mbuf *bufs[], uint16_t nr,
    struct rte_mbuf *out[], uint16_t *nout)
{
	struct dpdk_priv *d = w->d;
	union rte_ipsec_sad_key kkey[BURST_SZ];
	const union rte_ipsec_sad_key *keys[BURST_SZ];
	struct rte_mbuf *pm[BURST_SZ];
	void *sas[BURST_SZ];
	uint32_t nk = 0;
	uint16_t no = 0;

	if (nr > BURST_SZ) nr = BURST_SZ;

	for (uint16_t i = 0; i < nr; i++) {
		struct rte_ether_hdr *eh =
		    rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
		struct rte_ipv4_hdr *ip;
		struct rte_esp_hdr *es;
		uint8_t ihl;
		uint16_t ipsize;
		uint16_t natlen = 0;   /* NAT-T: extra 12 B (UDP hdr + 4-B marker) */

		/* Bounds-check against the FIRST segment (data_len), not the
		 * whole packet: a multi-segment or crafted frame must never make
		 * us read past the segment we pointer-walk. */
		if (rte_pktmbuf_data_len(bufs[i]) <
		    RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr))
			goto bad;                    /* too short for IP */
		ip = (struct rte_ipv4_hdr *)((uint8_t *)eh + RTE_ETHER_HDR_LEN);
		ihl = (ip->version_ihl & 0x0f) * 4;
		if (ihl < sizeof(struct rte_ipv4_hdr))   /* IHL < 5 */
			goto bad;
		/* NAT-T (RFC 3948): outer IP proto is UDP, dst port 4500, and the
		 * ESP packet follows a 4-byte non-ESP marker.  Detect it here so
		 * the encap (UDP hdr 8 + marker 4 = 12 B) can be stripped before
		 * librte_ipsec, which wants bare IP+ESP. */
		natlen = 0;
		if (ip->next_proto_id == IPPROTO_UDP) {
			const uint8_t *up;
			uint16_t dport;
			if (rte_pktmbuf_data_len(bufs[i]) <
			    RTE_ETHER_HDR_LEN + ihl + 8u + 4u)
				goto bad;
			up = (const uint8_t *)ip + ihl;
			dport = ((uint16_t)up[2] << 8) | up[3];
			if (dport == 4500 &&
			    up[8] == 0 && up[9] == 0 && up[10] == 0 && up[11] == 0)
				natlen = 8 + 4;   /* non-ESP marker present */
		}
		/* ESP header must fit within this segment after the IP header. */
		if (rte_pktmbuf_data_len(bufs[i]) <
		    RTE_ETHER_HDR_LEN + ihl + natlen + sizeof(*es))
			goto bad;
		/* IP total-length must match a sane minimum (don't trust it for
		 * crypto, but reject absurd values early). */
		ipsize = ntohs(ip->total_length);
		if (ipsize < ihl + natlen + sizeof(*es))
			goto bad;
		es = (struct rte_esp_hdr *)((uint8_t *)ip + ihl + natlen);

		/* librte_ipsec's inbound decrypt expects the bare IP+ESP packet
		 * (L2 already consumed), not the Ethernet-framed one the tap
		 * delivers.  Strip the L2 header and set l2_len=0 so the IP sits
		 * at offset 0; otherwise pofs is computed off-by-14 and the
		 * ciphertext/AAD/IV are read from the wrong bytes -> AUTH_FAILED
		 * on every real packet. */
		(void)rte_pktmbuf_adj(bufs[i], RTE_ETHER_HDR_LEN);
		ip = rte_pktmbuf_mtod(bufs[i], struct rte_ipv4_hdr *);
		if (natlen) {
			/* NAT-T: after the eth strip the frame is IP + UDP(8) +
			 * marker(4) + ESP.  rte_pktmbuf_adj would strip from the FRONT
			 * (the IP header), which is wrong.  Instead move the ESP payload
			 * down so it sits immediately after the IP header (bare IP + ESP
			 * for librte), then trim the now-empty UDP+marker tail. */
			int payload = rte_pktmbuf_pkt_len(bufs[i]) - ihl - natlen;
			uint8_t *base = rte_pktmbuf_mtod(bufs[i], uint8_t *);
			if (payload > 0)
				memmove(base + ihl, base + ihl + natlen,
				    (size_t)payload);
			if (natlen)
				rte_pktmbuf_trim(bufs[i], natlen);
			ip = rte_pktmbuf_mtod(bufs[i], struct rte_ipv4_hdr *);
			ip->next_proto_id = IPPROTO_ESP;
		}
		ihl = (ip->version_ihl & 0x0f) * 4;
		es = (struct rte_esp_hdr *)((uint8_t *)ip + ihl);

		bufs[i]->l2_len = 0;
		bufs[i]->l3_len = ihl;
		/* NOTE: do NOT set RTE_MBUF_F_RX_SEC_OFFLOAD here -- that flag
		 * marks a packet already decrypted by inline hardware and is
		 * only for hardware inline offload.  On the OpenSSL CPU-crypto
		 * path (session type NONE) setting it misleads the inbound
		 * prepare about the packet's crypto state. */
		bufs[i]->packet_type = RTE_PTYPE_L3_IPV4;
		if (d->verbose) {
			fprintf(stderr,
			    "r2dp-fwd: rx pkt_len=%u data_len=%u l2_len=%u l3_len=%u "
			    "nextproto=%u dip0=%02x%02x%02x%02x\n",
			    (unsigned)rte_pktmbuf_pkt_len(bufs[i]),
			    (unsigned)rte_pktmbuf_data_len(bufs[i]),
			    (unsigned)bufs[i]->l2_len, (unsigned)bufs[i]->l3_len,
			    (unsigned)ip->next_proto_id,
			    ((uint8_t *)&ip->dst_addr)[0],
			    ((uint8_t *)&ip->dst_addr)[1],
			    ((uint8_t *)&ip->dst_addr)[2],
			    ((uint8_t *)&ip->dst_addr)[3]);
		}
		kkey[nk].v4.spi = ntohl(es->spi);
		/* SAD key is keyed on (SPI, DIP) with DIP held in raw wire-order
		 * bytes -- addr4_to_u32 (SA insert) memcpy's rsa->dst.addr[0..4]
		 * verbatim, so match that exact numeric here, NO byte-swap.
		 * rte_be_to_cpu_32() would swap it and never match an installed
		 * SA (nlook==0 on every real packet). */
		kkey[nk].v4.dip = ip->dst_addr;
		if (d->verbose) {
			fprintf(stderr,
			    "r2dp-fwd: lookup spi=%08x dip=%08x (es.spi=%08x ip.dst=%08x)\n",
			    ntohl(es->spi), rte_be_to_cpu_32(ip->dst_addr),
			    es->spi, ip->dst_addr);
		}
		keys[nk] = &kkey[nk];
		pm[nk] = bufs[i];
		nk++;
		continue;
bad:
		/* malformed/undersized frame: drop it and move on so the rest of
		 * the burst is still processed (a `break` here would leak every
		 * remaining mbuf -- a remote pool-exhaustion DoS). */
		DROP(w, DR_MALFORMED, 1);
		rte_pktmbuf_free(bufs[i]);
	}
	if (nk == 0) {
		if (nout) *nout = 0;
		return 0;
	}

	uint32_t nlook = rte_ipsec_sad_lookup(d->sad, keys, sas, nk);

	if (d->verbose) {
		fprintf(stderr, "r2dp-fwd: esp_inbound nk=%u nlook=%u\n",
		    (unsigned)nk, (unsigned)nlook);
	}

	if (nlook == 0) {
		/* no SA matched -- drop the whole burst */
		DROP(w, DR_NO_SA_IN, nk);
		for (uint32_t i = 0; i < nk; i++)
			rte_pktmbuf_free(pm[i]);
		if (nout) *nout = 0;
		return nk;
	}

	/* Batch per run of packets on the same SA: one bulk op alloc, prepare,
	 * enqueue and dequeue per run instead of per packet. */
	for (uint32_t i = 0; i < nk; ) {
		struct rte_ipsec_session *ss = sas[i];
		struct rte_mbuf *ok[BURST_SZ];
		uint32_t j = i + 1;
		uint16_t ng;

		if (ss == NULL) {
			DROP(w, DR_NO_SA_IN, 1);
			rte_pktmbuf_free(pm[i]);   /* no SA: drop */
			i++;
			continue;
		}
		while (j < nk && sas[j] == ss)
			j++;
		ng = crypto_run(w, ss, &pm[i], (uint16_t)(j - i), ok);
		for (uint16_t k = 0; k < ng; k++) {
			/* D8: RFC 4301 s5.2 IN selector check + trim to inner IP */
			if (out && no < BURST_SZ && in_inner_ok(d, ss, ok[k])) {
				sa_bytes_add(d, ss, rte_pktmbuf_pkt_len(ok[k]));
				out[no++] = ok[k];
			} else {
				if (d->verbose)
					fprintf(stderr, "r2dp-fwd: inner SEL reject\n");
				DROP(w, DR_INNER_SEL, 1);
				rte_pktmbuf_free(ok[k]);
			}
		}
		i = j;
	}
	(void)nlook;
	if (nout) *nout = no;
	return nk;
}

static inline int
is_esp(struct rte_mbuf *mb)
{
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)
	    ((uint8_t *)rte_pktmbuf_mtod(mb, uint8_t *) + RTE_ETHER_HDR_LEN);
	if (rte_pktmbuf_pkt_len(mb) < RTE_ETHER_HDR_LEN +
	    sizeof(struct rte_ipv4_hdr))
		return 0;
	return (ip->version_ihl >> 4) == 4 && ip->next_proto_id == IPPROTO_ESP;
}

/* NAT-T (RFC 3948) ESP detection.  UDP/4500 is shared by ESP (the 4-byte
 * non-ESP marker then the ESP packet) and by IKE-over-NAT-T; the wire cannot
 * be trusted to tell them apart, so disambiguate by probing the inbound SAD:
 * only a frame whose (SPI, DIP) matches an installed NAT-T SA is ESP.  IKE
 * candidates stay on the exception path. */
static int
is_nat_esp(struct dpdk_priv *d, struct rte_mbuf *mb)
{
	uint8_t *p = rte_pktmbuf_mtod(mb, uint8_t *);
	uint32_t pl = rte_pktmbuf_pkt_len(mb);
	struct rte_ipv4_hdr *ip;
	struct rte_esp_hdr *es;
	uint8_t ihl;
	uint16_t dport;
	int i;

	if (pl < RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr))
		return 0;
	ip = (struct rte_ipv4_hdr *)(p + RTE_ETHER_HDR_LEN);
	if ((ip->version_ihl >> 4) != 4 || ip->next_proto_id != IPPROTO_UDP)
		return 0;
	ihl = (ip->version_ihl & 0x0f) * 4;
	if (ihl < sizeof(struct rte_ipv4_hdr))
		return 0;
	if (pl < RTE_ETHER_HDR_LEN + ihl + 8u + 4u)
		return 0;
	dport = ((uint16_t)p[RTE_ETHER_HDR_LEN + ihl + 2] << 8) |
	    p[RTE_ETHER_HDR_LEN + ihl + 3];
	/* non-ESP marker (4 zero bytes) must be present after the UDP hdr */
	if (dport != 4500 ||
	    p[RTE_ETHER_HDR_LEN + ihl + 8] || p[RTE_ETHER_HDR_LEN + ihl + 9] ||
	    p[RTE_ETHER_HDR_LEN + ihl + 10] || p[RTE_ETHER_HDR_LEN + ihl + 11])
		return 0;
	es = (struct rte_esp_hdr *)(p + RTE_ETHER_HDR_LEN + ihl + 12);
	/* is (SPI, outer-dst) an installed inbound SA?  Try each sa_tab entry. */
	for (i = 0; i < MAX_SA; i++) {
		const struct dp_sa *ds = &d->sa_tab[i];
		if (!sa_live(ds) || !ds->inbound)
			continue;
		if (ds->spi != ntohl(es->spi) || ds->dip != ip->dst_addr)
			continue;
		if (ds->natt == R2DP_NATT_ESPINUDP)
			return 1;
	}
	return 0;
}

static inline int
is_udp(struct rte_mbuf *mb)
{
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)
	    ((uint8_t *)rte_pktmbuf_mtod(mb, uint8_t *) + RTE_ETHER_HDR_LEN);
	if (rte_pktmbuf_pkt_len(mb) < RTE_ETHER_HDR_LEN +
	    sizeof(struct rte_ipv4_hdr))
		return 0;
	return (ip->version_ihl >> 4) == 4 && ip->next_proto_id == IPPROTO_UDP;
}

/* True for the M1 exception-path permit set: ARP, or IPv4 UDP to the IKE
 * ports (500 / 4500 NAT-T).  Everything else from the network must have
 * arrived protected and is dropped (H2). */
static int
is_ike_arp(struct rte_mbuf *mb)
{
	struct rte_ipv4_hdr *ip;
	uint8_t *p;
	uint16_t dport;
	int ihl;

	if (rte_pktmbuf_pkt_len(mb) < RTE_ETHER_HDR_LEN)
		return 0;
	/* ARP: ether_type 0x0806, no IPv4 header to parse */
	p = rte_pktmbuf_mtod(mb, uint8_t *);
	if (p[12] == 0x08 && p[13] == 0x06)
		return 1;
	/* not IPv4 (0x0800) -> not on the IKE/UDP permit path */
	if (p[12] != 0x08 || p[13] != 0x00)
		return 0;
	if (rte_pktmbuf_pkt_len(mb) < RTE_ETHER_HDR_LEN +
	    sizeof(struct rte_ipv4_hdr))
		return 0;
	ip = (struct rte_ipv4_hdr *)(p + RTE_ETHER_HDR_LEN);
	if ((ip->version_ihl >> 4) != 4 || ip->next_proto_id != IPPROTO_UDP)
		return 0;
	ihl = (ip->version_ihl & 0x0f) * 4;
	if (ihl < (int)sizeof(struct rte_ipv4_hdr))
		return 0;
	/* UDP header after the IPv4 header: dst port at +2 */
	{
		const uint8_t *u = p + RTE_ETHER_HDR_LEN + ihl;
		if ((size_t)(u - p) + 4 > rte_pktmbuf_pkt_len(mb))
			return 0;
		dport = (u[2] << 8) | u[3];
	}
	return dport == 500 || dport == 4500;
}

/* Recover the dp_sa owning an ipsec session handed back by the SAD. */
static inline struct dp_sa *
sa_of_sess(struct dpdk_priv *d, struct rte_ipsec_session *ss)
{
	struct dp_sa *ds = (struct dp_sa *)((uint8_t *)ss -
	    offsetof(struct dp_sa, sess));
	uintptr_t base = (uintptr_t)d->sa_tab, end = base + sizeof(d->sa_tab);

	return ((uintptr_t)ds >= base && (uintptr_t)ds < end) ? ds : NULL;
}

/* RFC 4301 s5.2 inbound check, tied to the SA the packet decrypted under.
 * The SA's IN (or FWD) PROTECT policies are those whose tunnel endpoints
 * are this SA's (tun_src = SA src = peer, tun_dst = SA dst = us) and, when
 * both carry a nonzero reqid, whose reqid matches.  The inner packet must
 * match one of them; a peer with a valid SA must not inject traffic for
 * another tunnel's selectors.  No policy for this SA => drop (default
 * deny).  Returns 1 to accept. */
static int
inbound_policy_ok(struct dpdk_priv *d, const struct dp_sa *ds,
    const uint8_t *ip, size_t avail)
{
	const struct dp_spd *s = __atomic_load_n(&d->spd, __ATOMIC_ACQUIRE);
	uint32_t j = (uint32_t)(ds - d->sa_tab);

	/* fast path: the snapshot's per-SA list, if it was built for this
	 * very SA install (gen match) */
	if (s && s->in_off && j < MAX_SA && s->in_gen[j] == ds->gen) {
		for (uint32_t k = s->in_off[j]; k < s->in_off[j + 1]; k++)
			if (r2dp_sel_match(s->in_pol[k], ip, avail))
				return 1;
		return 0;
	}
	/* snapshot not (yet) rebuilt for this SA: full scan */
	for (int i = 0; i < MAX_SA; i++) {
		const struct r2dp_sp *sp = sp_load(&d->sp_tab[i]);
		if (in_pol_fits(sp, ds) && r2dp_sel_match(sp, ip, avail))
			return 1;
	}
	return 0;
}

/* Validate + trim a decrypted inner packet and apply inbound_policy_ok. */
static int
in_inner_ok(struct dpdk_priv *d, struct rte_ipsec_session *ss,
    struct rte_mbuf *mb)
{
	struct rte_ipv4_hdr *ip;
	struct dp_sa *ds = sa_of_sess(d, ss);
	uint8_t ihl;
	uint16_t iplen, cur;

	if (ds == NULL || rte_pktmbuf_pkt_len(mb) < sizeof(struct rte_ipv4_hdr))
		return 0;
	ip = rte_pktmbuf_mtod(mb, struct rte_ipv4_hdr *);
	if ((ip->version_ihl >> 4) != 4)
		return 0;
	ihl = (ip->version_ihl & 0x0f) * 4;
	if (ihl < (uint8_t)sizeof(struct rte_ipv4_hdr) ||
	    ihl > rte_pktmbuf_data_len(mb))
		return 0;
	/* trim any trailing bytes beyond the inner IP length (padding/NAT-T) */
	iplen = rte_be_to_cpu_16(ip->total_length);
	cur = rte_pktmbuf_pkt_len(mb);
	if (iplen < cur)
		rte_pktmbuf_trim(mb, cur - iplen);
	return inbound_policy_ok(d, ds, (const uint8_t *)ip,
	    rte_pktmbuf_data_len(mb));
}

/* Find the EGRESS SA for this OUT policy.  racoon2 sends reqid=0 for every
 * SP and SA, so reqid alone would collapse all tunnels onto the first
 * outbound SA (H3).  Prefer an exact tunnel-endpoint match (policy tun_src/
 * tun_dst == SA src/dst); among endpoint matches prefer a real (nonzero)
 * reqid when the policy carries one; within each class take the newest SA
 * (highest install gen) so a rekey overlap encrypts with the new SA. */
static struct dp_sa *
sa_by_policy(struct dpdk_priv *d, const struct r2dp_sp *sp)
{
	struct dp_sa *by_reqid = NULL, *by_endpoint = NULL;
	uint32_t ts, td;
	int i;

	memcpy(&ts, &sp->tun_src.addr[0], 4);
	memcpy(&td, &sp->tun_dst.addr[0], 4);
	for (i = 0; i < MAX_SA; i++) {
		struct dp_sa *ds = &d->sa_tab[i];
		if (!sa_live(ds) || ds->inbound)
			continue;
		if (ds->srca != ts || ds->dsta != td)
			continue;
		/* Several outbound SAs can share a tunnel during a rekey overlap;
		 * the newest install (highest gen) is the one to encrypt with,
		 * never whichever happens to sit in the last table slot. */
		if (sp->reqid && ds->reqid == sp->reqid) {
			if (!by_reqid || ds->gen > by_reqid->gen)
				by_reqid = ds;
		} else if (!by_endpoint || ds->gen > by_endpoint->gen)
			by_endpoint = ds;
	}
	return by_reqid ? by_reqid : by_endpoint;
}

static int
pol_cmp(const void *a, const void *b)
{
	const struct dp_pol *x = a, *y = b;

	if (x->score != y->score)
		return y->score - x->score;      /* most specific first */
	return x->slot - y->slot;            /* then table order */
}

static void
spd_free(struct dp_spd *s)
{
	if (!s)
		return;
	if (s->acl)
		rte_acl_free(s->acl);
	free(s->out);
	free(s->in_off);
	free(s->in_gen);
	free(s->in_pol);
	free(s);
}

static const struct rte_acl_field_def acl_defs[AF_NUM] = {
	{ .type = RTE_ACL_FIELD_TYPE_BITMASK, .size = 1, .field_index = AF_PROTO,
	  .input_index = 0, .offset = offsetof(struct acl_key, proto) },
	{ .type = RTE_ACL_FIELD_TYPE_MASK, .size = 4, .field_index = AF_SRC,
	  .input_index = 1, .offset = offsetof(struct acl_key, src) },
	{ .type = RTE_ACL_FIELD_TYPE_MASK, .size = 4, .field_index = AF_DST,
	  .input_index = 2, .offset = offsetof(struct acl_key, dst) },
	{ .type = RTE_ACL_FIELD_TYPE_RANGE, .size = 2, .field_index = AF_SPORT,
	  .input_index = 3, .offset = offsetof(struct acl_key, sport) },
	{ .type = RTE_ACL_FIELD_TYPE_RANGE, .size = 2, .field_index = AF_DPORT,
	  .input_index = 3, .offset = offsetof(struct acl_key, dport) },
};

static uint32_t
be32_of(const uint8_t *a)
{
	return (uint32_t)a[0] << 24 | (uint32_t)a[1] << 16 |
	    (uint32_t)a[2] << 8 | a[3];
}

/* Build an rte_acl classifier over s->out[] (already sorted).  Policies a
 * full scan could never match (non-IPv4 selector, prefix > 32) get no rule.
 * Priority = score, then table slot (lower first): the same winner as
 * r2dp_sel_match + r2dp_sel_score over sp_tab.  Built entirely to the side:
 * on any failure the caller publishes nothing. */
static int
spd_build_acl(struct dp_spd *s)
{
	static uint32_t gen;
	struct rte_acl_param prm;
	struct rte_acl_config cfg;
	struct dp_acl_rule *rules;
	char name[RTE_ACL_NAMESIZE];
	uint32_t n = 0;
	int ret = -ENOMEM;

	s->acl = NULL;
	if (!s->nout)
		return 0;
	rules = calloc(s->nout, sizeof(*rules));
	if (!rules)
		return -ENOMEM;
	for (uint32_t i = 0; i < s->nout; i++) {
		const struct r2dp_sp *sp = s->out[i].sp;
		struct dp_acl_rule *r = &rules[n];

		if (sp->sel_src.family != R2DP_AF_INET4 ||
		    sp->sel_dst.family != R2DP_AF_INET4 ||
		    sp->pref_src > 32 || sp->pref_dst > 32)
			continue;
		r->data.category_mask = 1;
		r->data.priority = s->out[i].score * 1024 +
		    (MAX_SA - 1 - s->out[i].slot) + 1;
		r->data.userdata = i + 1;
		if (sp->ul_proto != R2DP_PROTO_ANY) {
			r->field[AF_PROTO].value.u8 = sp->ul_proto;
			r->field[AF_PROTO].mask_range.u8 = 0xff;
		}
		r->field[AF_SRC].value.u32 = be32_of(sp->sel_src.addr);
		r->field[AF_SRC].mask_range.u32 = sp->pref_src;
		r->field[AF_DST].value.u32 = be32_of(sp->sel_dst.addr);
		r->field[AF_DST].mask_range.u32 = sp->pref_dst;
		r->field[AF_SPORT].value.u16 = sp->sel_src.port ?
		    rte_be_to_cpu_16(sp->sel_src.port) : 0;
		r->field[AF_SPORT].mask_range.u16 = sp->sel_src.port ?
		    rte_be_to_cpu_16(sp->sel_src.port) : 0xffff;
		r->field[AF_DPORT].value.u16 = sp->sel_dst.port ?
		    rte_be_to_cpu_16(sp->sel_dst.port) : 0;
		r->field[AF_DPORT].mask_range.u16 = sp->sel_dst.port ?
		    rte_be_to_cpu_16(sp->sel_dst.port) : 0xffff;
		n++;
	}
	if (!n) {
		free(rules);
		return 0;
	}
	snprintf(name, sizeof(name), "r2dp_spd_%u", __atomic_add_fetch(&gen, 1, __ATOMIC_RELAXED));
	memset(&prm, 0, sizeof(prm));
	prm.name = name;
	prm.socket_id = SOCKET_ID_ANY;
	prm.rule_size = RTE_ACL_RULE_SZ(AF_NUM);
	prm.max_rule_num = n;
	s->acl = rte_acl_create(&prm);
	if (!s->acl)
		goto out;
	if (rte_acl_add_rules(s->acl, (const struct rte_acl_rule *)rules, n) != 0)
		goto out;
	memset(&cfg, 0, sizeof(cfg));
	cfg.num_categories = 1;
	cfg.num_fields = AF_NUM;
	memcpy(cfg.defs, acl_defs, sizeof(acl_defs));
	if (rte_acl_build(s->acl, &cfg) != 0)
		goto out;
	ret = 0;
out:
	free(rules);
	if (ret && s->acl) {
		rte_acl_free(s->acl);
		s->acl = NULL;
	}
	return ret;
}

/* Fill an ACL key from an inner IPv4 header; 0 if it is not classifiable
 * (r2dp_sel_match would match nothing). */
static inline int
acl_key_fill(struct acl_key *k, const uint8_t *ip, size_t avail)
{
	size_t ihl;

	memset(k, 0, sizeof(*k));
	if (avail < 20 || (ip[0] >> 4) != 4)
		return 0;
	ihl = (size_t)(ip[0] & 0x0f) * 4;
	if (ihl < 20 || ihl > avail)
		return 0;
	k->proto = ip[9];
	memcpy(&k->src, ip + 12, 4);
	memcpy(&k->dst, ip + 16, 4);
	if ((k->proto == 6 || k->proto == 17 || k->proto == 132) &&
	    ((ip[6] & 0x1f) | ip[7]) == 0 && avail >= ihl + 4) {
		memcpy(&k->sport, ip + ihl, 2);
		memcpy(&k->dport, ip + ihl + 2, 2);
	}
	return 1;
}

/* Build a new snapshot from sp_tab/sa_tab, publish it, wait a grace period,
 * free the old one.  Caller holds d->lock.  On allocation failure nothing is
 * published and the worker keeps the previous snapshot. */
static inline uint32_t
peer_hash(uint32_t ip)
{
	return (ip * 2654435761u) >> 20;     /* 12 bits = PEER_HSZ */
}

static void
peer_put(struct dp_spd *s, uint32_t ip)
{
	uint32_t h;

	if (ip == 0) { s->peer_zero = 1; return; }
	for (h = peer_hash(ip); s->peer[h] && s->peer[h] != ip;
	    h = (h + 1) & (PEER_HSZ - 1))
		;
	s->peer[h] = ip;
}

/* IN/FWD PROTECT policy `sp` may admit traffic decrypted by SA `ds`. */
static int
in_pol_fits(const struct r2dp_sp *sp, const struct dp_sa *ds)
{
	uint32_t ts, td;

	if (!sp || sp->action != R2DP_ACT_PROTECT ||
	    (sp->dir != R2DP_DIR_IN && sp->dir != R2DP_DIR_FWD))
		return 0;
	memcpy(&ts, &sp->tun_src.addr[0], 4);
	memcpy(&td, &sp->tun_dst.addr[0], 4);
	if (ts != ds->srca || td != ds->dsta)
		return 0;
	if (sp->reqid && ds->reqid && sp->reqid != ds->reqid)
		return 0;
	return 1;
}

/* Inbound per-SA policy index + peer hash (control time, d->lock held). */
static int
spd_build_in(struct dpdk_priv *d, struct dp_spd *s)
{
	uint32_t tot = 0, k = 0;

	s->in_off = calloc(MAX_SA + 1, sizeof(*s->in_off));
	s->in_gen = calloc(MAX_SA, sizeof(*s->in_gen));
	if (!s->in_off || !s->in_gen)
		return -ENOMEM;
	for (int pass = 0; pass < 2; pass++) {
		k = 0;
		for (int j = 0; j < MAX_SA; j++) {
			const struct dp_sa *ds = &d->sa_tab[j];
			if (pass)
				s->in_off[j] = k;
			if (!sa_live(ds) || !ds->inbound)
				continue;
			if (pass)
				s->in_gen[j] = ds->gen;
			for (int i = 0; i < MAX_SA; i++) {
				const struct r2dp_sp *sp = d->sp_tab[i].sp;
				if (!in_pol_fits(sp, ds))
					continue;
				if (pass)
					s->in_pol[k] = sp;
				k++;
			}
		}
		if (!pass) {
			tot = k;
			s->in_pol = calloc(tot ? tot : 1, sizeof(*s->in_pol));
			if (!s->in_pol)
				return -ENOMEM;
		}
	}
	s->in_off[MAX_SA] = k;
	for (int j = 0; j < MAX_SA; j++) {
		const struct dp_sa *ds = &d->sa_tab[j];
		if (sa_live(ds))
			peer_put(s, ds->inbound ? ds->srca : ds->dsta);
	}
	for (int i = 0; i < MAX_SA; i++) {
		const struct r2dp_sp *sp = d->sp_tab[i].sp;
		uint32_t a;
		if (!sp || sp->action != R2DP_ACT_PROTECT)
			continue;
		if (sp->dir == R2DP_DIR_OUT)
			memcpy(&a, &sp->tun_dst.addr[0], 4);
		else if (sp->dir == R2DP_DIR_IN)
			memcpy(&a, &sp->tun_src.addr[0], 4);
		else
			continue;
		peer_put(s, a);
	}
	return 0;
}

static int
spd_rebuild_ex(struct dpdk_priv *d, int policies_changed)
{
	struct dp_spd *ns, *old;
	uint32_t n = 0;

	ns = calloc(1, sizeof(*ns));
	if (!ns)
		goto fail;
	ns->out = calloc(MAX_SA, sizeof(*ns->out));
	if (!ns->out)
		goto fail;
	for (int i = 0; i < MAX_SA; i++) {
		const struct r2dp_sp *sp = d->sp_tab[i].sp;
		struct dp_pol *p;
		struct dp_sa *ds;

		if (!sp || sp->dir != R2DP_DIR_OUT)
			continue;
		p = &ns->out[n++];
		p->sp = sp;
		p->slot = i;
		p->score = r2dp_sel_score(sp);
		p->sa_idx = -1;
		if (sp->action == R2DP_ACT_PROTECT &&
		    (ds = sa_by_policy(d, sp)) != NULL) {
			p->sa_idx = (int32_t)(ds - d->sa_tab);
			p->sa_gen = ds->gen;
		}
	}
	ns->nout = n;
	qsort(ns->out, n, sizeof(*ns->out), pol_cmp);
	if (spd_build_in(d, ns) < 0)
		goto fail;

	old = d->spd;
	if (!policies_changed && old && old->nout == n) {
		/* only bindings changed (SA install/delete): out[] has the same
		 * policies in the same order, so the classifier is reused */
		ns->acl = old->acl;
	} else if (spd_build_acl(ns) < 0)
		goto fail;
	__atomic_store_n(&d->spd, ns, __ATOMIC_RELEASE);
	if (old) {
		if (old->acl == ns->acl)
			old->acl = NULL;     /* ownership moved to ns */
		if (d->rcu)
			rte_rcu_qsbr_synchronize(d->rcu, RTE_QSBR_THRID_INVALID);
		spd_free(old);
	}
	return 0;
fail:
	spd_free(ns);
	d->n_spd_fail++;
	return -ENOMEM;
}

/* Control-side teardown (dpd_stop / tests): free the snapshot and SP copies. */
static void
spd_teardown(struct dpdk_priv *d)
{
	spd_free(d->spd);
	d->spd = NULL;
	for (int i = 0; i < MAX_SA; i++) {
		free(d->sp_tab[i].sp);
		d->sp_tab[i].sp = NULL;
	}
}

/* Resolve a classified OUT policy (index+1 from the ACL, 0 = none) to the
 * policy and its control-time bound EGRESS SA (*sa NULL if none, or if the
 * binding went stale: retired/reused slot => generation mismatch => fail
 * closed). */
static inline const struct r2dp_sp *
spd_resolve(struct dpdk_priv *d, const struct dp_spd *s, uint32_t res,
    struct dp_sa **sa)
{
	const struct dp_pol *p;

	*sa = NULL;
	if (!res || res > s->nout)
		return NULL;
	p = &s->out[res - 1];
	if (p->sp->action == R2DP_ACT_PROTECT && p->sa_idx >= 0) {
		struct dp_sa *ds = &d->sa_tab[p->sa_idx];
		if (sa_live(ds) && ds->gen == p->sa_gen && !ds->inbound)
			*sa = ds;
	}
	return p->sp;
}

/* Most specific OUT policy for one inner IPv4 packet (rte_acl over the
 * published snapshot); DISCARD/BYPASS can override PROTECT (M6), port
 * selectors are honoured (M5).  The burst path classifies all at once. */
static const struct r2dp_sp *
sp_match_out(struct dpdk_priv *d, const struct rte_ipv4_hdr *ip, size_t avail,
    struct dp_sa **sa)
{
	const struct dp_spd *s = __atomic_load_n(&d->spd, __ATOMIC_ACQUIRE);
	struct acl_key k;
	const uint8_t *data[1] = { (const uint8_t *)&k };
	uint32_t res = 0;

	*sa = NULL;
	if (!s || !s->acl || !acl_key_fill(&k, (const uint8_t *)ip, avail))
		return NULL;
	if (rte_acl_classify(s->acl, data, &res, 1, 1) != 0)
		return NULL;
	return spd_resolve(d, s, res, sa);
}

/* Outbound ESP: take inner IPv4 plaintext (L2 already stripped, l2_len=0),
 * look up the OUT policy + EGRESS SA, run rte_ipsec EGRESS encrypt, and write
 * the resulting ESP datagram (outer IP + ESP, L2 NOT yet re-added) into `out`.
 * Non-protected packets are left alone (returned as unchanged bypass). */
static void
esp_outbound(struct dp_worker *w, struct rte_mbuf *bufs[], uint16_t nr,
    struct rte_mbuf *out[], uint16_t *nout, uint16_t *nbypass)
{
	struct dpdk_priv *d = w->d;
	uint16_t no = 0, nb = 0, nm = 0;
	struct rte_mbuf *pm[BURST_SZ];
	struct dp_sa *pds[BURST_SZ];
	enum dp_drop why = DR_MALFORMED;

	if (nr > BURST_SZ) nr = BURST_SZ;
	for (uint16_t i = 0; i < nr; i++) {
		struct dp_sa *ds;
		const struct r2dp_sp *sp;
		uint8_t ihl;
		struct rte_ipv4_hdr *ip, *lip;

		/* inner tap delivers Ethernet: parse the inner IP at the L2 offset
		 * for policy matching; only STRIP L2 below for a matched packet so
		 * the unconsumed (bypass) mbufs keep their frame for forwarding. */
		if (rte_pktmbuf_pkt_len(bufs[i]) <
		    RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr)) {
			nb++; continue;
		}
		ip = (struct rte_ipv4_hdr *)((uint8_t *)
		    rte_pktmbuf_mtod(bufs[i], uint8_t *) + RTE_ETHER_HDR_LEN);
		if ((ip->version_ihl >> 4) != 4) { nb++; continue; }
		sp = sp_match_out(d, ip, rte_pktmbuf_data_len(bufs[i]) -
		    RTE_ETHER_HDR_LEN, &ds);
		if (!sp) { nb++; continue; }   /* no matching OUT policy: bypass */

		/* A matched policy decides the disposition (H2, RFC 4301 5.1):
		 * DISCARD always drops; PROTECT with no SA drops (fail-closed, the
		 * SA must exist before we protect); only BYPASS forwards clear. */
		why = DR_POLICY_DISCARD;
		if (sp->action == R2DP_ACT_DISCARD)
			goto drop;
		why = DR_NO_SA_OUT;
		if (sp->action == R2DP_ACT_PROTECT && !ds)
			goto drop;
		if (sp->action != R2DP_ACT_PROTECT) { nb++; continue; } /* BYPASS */

		/* Once the packet matched a policy, failure below must DROP it, never
		 * leak it back as cleartext: the L2 header is about to be stripped,
		 * so the mbuf is no longer a forwardable frame (H4/H2). */
		(void)rte_pktmbuf_adj(bufs[i], RTE_ETHER_HDR_LEN);
		bufs[i]->l2_len = 0;
		lip = rte_pktmbuf_mtod(bufs[i], struct rte_ipv4_hdr *);
		ihl = (lip->version_ihl & 0x0f) * 4;
		why = DR_MALFORMED;
		if (ihl < 20 || ihl > rte_pktmbuf_data_len(bufs[i]))
			goto drop;   /* M5c: reject malformed/oversized IHL */
		bufs[i]->l3_len = ihl;
		bufs[i]->packet_type = RTE_PTYPE_L3_IPV4;
		/* M5a: drop Ethernet padding.  A short inner IP (< 60B with the tap's
		 * eth frame) carries trailing pad after ip->total_length; that pad
		 * would be encrypted into the ESP payload and break the inner ICV at
		 * a real peer that authenticated only the padded length.  Trim to
		 * the IP length so the ESP payload carries exactly the inner packet. */
		{
			uint16_t iplen = rte_be_to_cpu_16(lip->total_length);
			uint16_t cur = rte_pktmbuf_pkt_len(bufs[i]);
			if (iplen < cur)
				rte_pktmbuf_trim(bufs[i], cur - iplen);
		}

		/* matched + PROTECT + SA: queue for the batched crypto pass */
		pm[nm] = bufs[i];
		pds[nm++] = ds;
		bufs[i] = NULL;
		continue;
drop:
		/* Single drop path: never forward cleartext after a policy matched,
		 * and never leak the mbuf (H4).  Count and mark the slot NULL so
		 * worker_inner does not forward or free it again. */
		DROP(w, why, 1);
		rte_pktmbuf_free(bufs[i]);
		bufs[i] = NULL;
	}

	/* batched crypto, one run per SA (bursts are usually one flow) */
	for (uint16_t i = 0; i < nm; ) {
		struct dp_sa *ds = pds[i];
		struct rte_mbuf *ok[BURST_SZ];
		uint16_t j = i + 1, ng;

		while (j < nm && pds[j] == ds)
			j++;
		ng = crypto_run(w, &ds->sess, &pm[i], j - i, ok);
		for (uint16_t k = 0; k < ng; k++) {
			struct rte_mbuf *m = ok[k];
			uint16_t proc = 1;

			if (!out || no >= BURST_SZ) {
				DROP(w, DR_NOMEM, 1);
				rte_pktmbuf_free(m);
				continue;
			}
			/* byte-lifetime: count the crypted bytes on this egress SA */
			__atomic_fetch_add(&ds->bytes, rte_pktmbuf_pkt_len(m),
			    __ATOMIC_RELAXED);
			{
				struct rte_ipv4_hdr *oip =
				    rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
				/* NAT-T egress: insert UDP(8)+marker(4) after the outer IP
				 * and retag proto to UDP (RFC 3948).  memmove the ESP part
				 * up 12 B, then fill UDP hdr (sport/dport 4500) + marker. */
				if (ds->natt == R2DP_NATT_ESPINUDP && oip &&
				    (oip->version_ihl >> 4) == 4) {
					uint8_t ihl = (oip->version_ihl & 0x0f) * 4;
					uint32_t len = rte_pktmbuf_pkt_len(m);
					uint8_t *base = rte_pktmbuf_mtod(m, uint8_t*);
					uint16_t plen;
					if (rte_pktmbuf_append(m, 12)) {
						memmove(base + ihl + 12, base + ihl,
						    len - ihl);
						base[ihl+0] = 0x11; base[ihl+1] = 0x94;
						base[ihl+2] = 0x11; base[ihl+3] = 0x94;
						plen = (uint16_t)(len - ihl + 12);
						base[ihl+4] = plen >> 8; base[ihl+5] = plen & 0xff;
						base[ihl+6] = 0; base[ihl+7] = 0;  /* UDP csum */
						base[ihl+8]=0;base[ihl+9]=0;base[ihl+10]=0;base[ihl+11]=0;
						oip->next_proto_id = IPPROTO_UDP;
						/* bump outer IP total_length by the 12 encap bytes */
						{
						uint16_t tl = (
						    ((uint16_t)base[2] << 8) | base[3]) + 12;
						base[2] = tl >> 8; base[3] = tl & 0xff;
						}
						oip->hdr_checksum = 0;
					}
				}
				/* librte's outbound tunnel prepare only patches
				 * total_length/packet_id; it leaves hdr_checksum=0, which
				 * every real peer drops (ip_rcv -> InHdrErrors).  Compute
				 * it here (H1). */
				if ((oip->version_ihl >> 4) == 4) {
					oip->hdr_checksum = 0;
					oip->hdr_checksum = rte_ipv4_cksum(oip);
				}
				if (d->verbose) {
					uint8_t *b = rte_pktmbuf_mtod(m, uint8_t *);
					fprintf(stderr,
					    "r2dp-fwd: egress-proc proc=%u pkt=%u b0=%02x%02x%02x%02x%02x%02x%02x%02x\n",
					    proc, (unsigned)rte_pktmbuf_pkt_len(m),
					    b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]);
				}
			}
			(void)proc;
			w->n_esp++;
			out[no++] = m;
		}
		i = j;
	}
	if (nout) *nout = no;
	if (nbypass) *nbypass = nb;
}

/* Process a burst received on the OUTER tap (ESP side): ESP -> decrypt ->
 * forward the inner (cleartext) packet out the inner tap; non-ESP (IKE, ARP)
 * is the exception path and crosses to the inner (kernel) side.
 *
 * Classify ONCE into separate arrays.  Compacting in place
 * (bufs[nesp]=bufs[i]) overwrites the slots that still hold unclassified
 * mbufs, and re-scanning bufs[] afterwards re-reads ESP mbufs that
 * esp_inbound() already stripped and freed -- a doble-handling/double-free.
 * Never touch bufs[] again after the single pass below. */
/* Is `ip` (raw wire order) the far end of a configured tunnel?  Far end =
 * src of an inbound SA, dst of an outbound SA, or tun_dst/tun_src of a
 * PROTECT OUT/IN policy (policies exist before IKE completes, so the
 * initiator can learn from the peer's IKE replies). */
static int
is_tunnel_peer(struct dpdk_priv *d, uint32_t ip)
{
	const struct dp_spd *s = __atomic_load_n(&d->spd, __ATOMIC_ACQUIRE);

	if (!s)
		return 0;
	if (ip == 0)
		return s->peer_zero;
	for (uint32_t h = peer_hash(ip); s->peer[h];
	    h = (h + 1) & (PEER_HSZ - 1))
		if (s->peer[h] == ip)
			return 1;
	return 0;
}

static void
worker_outer(struct dp_worker *w, int port)
{
	struct dpdk_priv *d = w->d;
	struct rte_mbuf *bufs[BURST_SZ];
	struct rte_mbuf *esp[BURST_SZ], *exc[BURST_SZ];
	uint16_t nr = rte_eth_rx_burst(port, w->qid, bufs, BURST_SZ);

	if (nr == 0)
		return;
	w->n_rx += nr;
	if (d->verbose) {
		/* Dump the first raw frame as the tap delivered it, BEFORE any L2
		 * strip, so we can compare it byte-for-byte against what was
		 * injected (esp.bin wrapped in eth).  If these don't match, the
		 * tap/framing assumption is wrong and every offset downstream is
		 * garbage. */
		struct rte_mbuf *f = bufs[0];
		uint8_t *fr = rte_pktmbuf_mtod(f, uint8_t *);
		uint32_t fl = rte_pktmbuf_pkt_len(f);
		fprintf(stderr, "r2dp-fwd: RX raw pkt_len=%u data_len=%u data_off=%u: ",
		    fl, (unsigned)rte_pktmbuf_data_len(f),
		    (unsigned)rte_pktmbuf_headroom(f));
		for (uint32_t z = 0; z < 40 && z < fl; z++)
			fprintf(stderr, "%02x", fr[z]);
		fprintf(stderr, "\n");
	}
	uint16_t nesp = 0, nex = 0;
	for (uint16_t i = 0; i < nr; i++) {
		/* Learn the peer's MAC (keyed by its IP) only from unicast
		 * IKE/ESP whose source is a configured tunnel peer, so an
		 * arbitrary host on the segment cannot capture egress ESP;
		 * relearn when the peer's MAC changes (N1). */
		{
			uint32_t sip;
			const uint8_t *smac;
			if (r2dp_nh_frame_ike_esp(rte_pktmbuf_mtod(bufs[i],
			    const uint8_t *), rte_pktmbuf_data_len(bufs[i]),
			    &sip, &smac) && is_tunnel_peer(d, sip)) {
				int lr = r2dp_nh_learn(&w->nh, sip, smac,
				    rte_get_tsc_cycles());
				if (lr > 0 && d->verbose)
					fprintf(stderr, "r2dp-fwd: %s next hop for "
					    "peer %08x: %02x:%02x:%02x:%02x:%02x:%02x\n",
					    lr == 2 ? "relearned" : "learned", sip,
					    smac[0], smac[1], smac[2], smac[3],
					    smac[4], smac[5]);
			}
		}
		if (is_esp(bufs[i]) || is_nat_esp(d, bufs[i])) {
			w->n_esp++;
			esp[nesp++] = bufs[i];
		} else {
			exc[nex++] = bufs[i];
		}
	}

	if (nesp) {
		struct rte_mbuf *dec[BURST_SZ];
		uint16_t ndec = 0;
		esp_inbound(w, esp, nesp, dec, &ndec);
		if (ndec) {
			/* rte_ipsec_pkt_process leaves the decrypted INNER packet as
			 * bare IP (l2_len=0, no Ethernet header).  net_tap transmits
			 * the mbuf into the kernel tap as an Ethernet frame, so a
			 * header must be prepended or the tap sees a frameless
			 * <64-byte packet and the peer never receives the inner
			 * IP.  Fabricate a minimal eth header (dummy MACs -- the
			 * next hop reads the inner IP; this matches ipsec-secgw's
			 * tunneled-inner handling). */
			for (uint16_t i = 0; i < ndec; i++) {
				struct rte_ether_hdr *eh;
				char *h = rte_pktmbuf_prepend(dec[i],
				    RTE_ETHER_HDR_LEN);
				if (h == NULL) {   /* no headroom: drop */
					DROP(w, DR_NOMEM, 1);
					rte_pktmbuf_free(dec[i]);
					dec[i] = NULL;
					continue;
				}
				eh = rte_pktmbuf_mtod(dec[i],
				    struct rte_ether_hdr *);
				/* Deliver each decrypted inner packet UNICAST to the inner
				 * (plaintext host) tap's own MAC.  A broadcast dst here
				 * makes the host kernel classify the frame PACKET_BROADCAST,
				 * and Linux tcp_v4_rcv drops pkt_type != PACKET_HOST
				 * before counting InSegs -- so TCP over the tunnel would
				 * silently never handshake while UDP/ICMP (which accept
				 * broadcast) passed.  icmp/udp also work unicast. */
				{
					memset(eh->dst_addr.addr_bytes, 0,
					    RTE_ETHER_ADDR_LEN);
					memcpy(eh->dst_addr.addr_bytes, w->our_inner_mac, 6);
					memset(eh->src_addr.addr_bytes, 0,
					    RTE_ETHER_ADDR_LEN);
					memcpy(eh->src_addr.addr_bytes, w->our_inner_mac, 6);
				}
				eh->ether_type = htons(RTE_ETHER_TYPE_IPV4);
				dec[i]->l2_len = RTE_ETHER_HDR_LEN;
				/* bump l3_len so inner IP is at eth+ip */
				dec[i]->l3_len = 20;
				/* Linux tap drops Ethernet frames shorter than the
				 * 60-byte (non-VLAN) minimum.  A 44-byte decrypted ICMP
				 * + 14 eth = 58, so pad the L2 frame to 60. */
				{
					uint32_t cur = rte_pktmbuf_pkt_len(dec[i]);
					uint32_t need = RTE_ETHER_MIN_LEN;
					if (cur < need) {
						void *pad = rte_pktmbuf_append(dec[i],
						    need - cur);
						if (pad)
							memset(pad, 0, need - cur);
					}
				}
			}
			uint16_t to = (d->inner_port >= 0) ? d->inner_port : port;
			uint16_t ntx = 0;
			struct rte_mbuf *txq[BURST_SZ];
			for (uint16_t i = 0; i < ndec; i++)
				if (dec[i])
					txq[ntx++] = dec[i];
			uint16_t sent = rte_eth_tx_burst(to, w->qid, txq, ntx);
			w->n_tx += sent;
			DROP(w, DR_TX_FULL, ntx - sent);
			if (d->verbose)
				fprintf(stderr, "r2dp-fwd: esp-tx ndec=%u ntx=%u sent=%u\n",
				    ndec, ntx, sent);
			for (uint16_t i = sent; i < ntx; i++)
				rte_pktmbuf_free(txq[i]);
		}
		/* esp_inbound owns and frees every ESP mbuf (matched or not). */
	}
	/* non-ESP: exception path -> the kernel side.  H2: don't fail open --
	 * only IKE (UDP 500/4500) and ARP cross; other cleartext from the network
	 * (which should have arrived under an IN PROTECT SA) is dropped. */
	if (nex) {
		uint16_t to = (d->inner_port >= 0) ? d->inner_port : port;
		uint16_t nf = 0;
		struct rte_mbuf *fwd[BURST_SZ];
		for (uint16_t i = 0; i < nex; i++) {
			if (is_ike_arp(exc[i]))
				fwd[nf++] = exc[i];
			else
				DROP(w, DR_CLEAR_OUTER, 1);
		}
		if (nf) {
			if (is_udp(fwd[0]))
				w->n_ike += nf;   /* IKE */
			uint16_t sent = rte_eth_tx_burst(to, w->qid, fwd, nf);
			w->n_tx += sent;
			DROP(w, DR_TX_FULL, nf - sent);
			for (uint16_t i = sent; i < nf; i++)
				rte_pktmbuf_free(fwd[i]);
		}
		/* dropped-exception mbufs are freed here */
		for (uint16_t i = 0; i < nex; i++)
			if (!is_ike_arp(exc[i]))
				rte_pktmbuf_free(exc[i]);
	}
}

/* Process a burst received on the INNER tap (plaintext/kernel side):
 * protected IPv4 gets encrypted by esp_outbound (EGRESS) and tx'd to the outer
 * tap as ESP; non-protected (IKE/ARP, or no OUT policy -> bypass) crosses to
 * the outer (peer) tap on the exception path.  ESP arriving here is dropped. */
static void
worker_inner(struct dp_worker *w, int port)
{
	struct dpdk_priv *d = w->d;
	struct rte_mbuf *bufs[BURST_SZ];
	uint16_t nr = rte_eth_rx_burst(port, w->qid, bufs, BURST_SZ);

	if (nr == 0)
		return;
	w->n_rx += nr;

	/* 1. classify: ESP here is anomalous -> drop; non-ESP may be protected
	 *    (encrypt) or unprotected (IKE/ARP -> exception path). */
	struct rte_mbuf *nonesp[BURST_SZ];
	uint16_t nnon = 0;
	for (uint16_t i = 0; i < nr; i++) {
		if (is_esp(bufs[i])) {
			DROP(w, DR_ESP_ON_INNER, 1);
			rte_pktmbuf_free(bufs[i]);
		}
		else
			nonesp[nnon++] = bufs[i];
	}
	if (nnon == 0)
		return;

	/* 2. encrypt the protected subset.  esp_outbound consumes the mbufs with
	 *    a matching OUT policy into esp_out[] (as ESP datagrams, no L2) and
	 *    leaves the unmatched ones (nby) untouched in nonesp[]. */
	struct rte_mbuf *esp_out[BURST_SZ];
	uint16_t nout = 0, nby = 0;
	esp_outbound(w, nonesp, nnon, esp_out, &nout, &nby);

	/* 3. prepend L2 to the ESP datagrams and tx to the outer (peer) tap */
	if (nout) {
		uint16_t ntx = 0;
		struct rte_mbuf *txq[BURST_SZ];
		uint16_t to = (d->port_id >= 0) ? d->port_id : port;
		for (uint16_t i = 0; i < nout; i++) {
			struct rte_ether_hdr *eh;
			char *h = rte_pktmbuf_prepend(esp_out[i], RTE_ETHER_HDR_LEN);
			if (!h) { DROP(w, DR_NOMEM, 1); rte_pktmbuf_free(esp_out[i]); continue; }
			eh = rte_pktmbuf_mtod(esp_out[i], struct rte_ether_hdr *);
			/* Egress ESP is unicast to the tunnel peer's learned
			 * next hop (keyed by the outer destination IP).  With
			 * no learned MAC, drop: broadcasting ESP would spray it
			 * to every host on the segment (N2). */
			{
				const struct rte_ipv4_hdr *oip =
				    (const struct rte_ipv4_hdr *)(eh + 1);
				uint32_t odst;
				const uint8_t *nmac;
				memcpy(&odst, &oip->dst_addr, 4);
				nmac = r2dp_nh_lookup(&w->nh, odst);
				if (nmac == NULL) {
					DROP(w, DR_NO_NEXTHOP, 1);
					rte_pktmbuf_free(esp_out[i]);
					continue;
				}
				memcpy(eh->dst_addr.addr_bytes, nmac, 6);
				memcpy(eh->src_addr.addr_bytes, w->our_mac, 6);
			}
			eh->ether_type = htons(RTE_ETHER_TYPE_IPV4);
			esp_out[i]->l2_len = RTE_ETHER_HDR_LEN;
			esp_out[i]->l3_len = 20;
			{   /* pad to Ethernet minimum (tap drops short frames) */
				uint32_t cur = rte_pktmbuf_pkt_len(esp_out[i]);
				if (cur < RTE_ETHER_MIN_LEN) {
					void *pad = rte_pktmbuf_append(esp_out[i],
					    RTE_ETHER_MIN_LEN - cur);
					if (pad) memset(pad, 0, RTE_ETHER_MIN_LEN - cur);
				}
			}
			txq[ntx++] = esp_out[i];
		}
		uint16_t sent = rte_eth_tx_burst(to, w->qid, txq, ntx);
		w->n_tx += sent;
		DROP(w, DR_TX_FULL, ntx - sent);
		if (d->verbose)
			fprintf(stderr, "r2dp-fwd: egress-tx nout=%u ntx=%u sent=%u\n",
			    nout, ntx, sent);
		for (uint16_t i = sent; i < ntx; i++)
			rte_pktmbuf_free(txq[i]);
	}

	/* 4. exception path: the unmatched non-ESP packets (IKE/ARP/clear bypass)
	 *    cross to the outer (peer) tap as-is.  These are the nby mbufs still
	 *    held in nonesp[] (esp_outbound did not consume them). */
	if (nby) {
		uint16_t ntx = 0;
		struct rte_mbuf *txq[BURST_SZ];
		uint16_t to = (d->port_id >= 0) ? d->port_id : port;
		/* esp_outbound NULLs every slot it consumed or dropped, so
		 * the survivors are exactly the bypass set (O(n), was O(n^2)) */
		for (uint16_t i = 0; i < nnon; i++)
			if (nonesp[i] != NULL)
				txq[ntx++] = nonesp[i];
		if (ntx && is_udp(txq[0]))
			w->n_ike += ntx;
		uint16_t sent = rte_eth_tx_burst(to, w->qid, txq, ntx);
		w->n_tx += sent;
		DROP(w, DR_TX_FULL, ntx - sent);
		for (uint16_t i = sent; i < ntx; i++)
			rte_pktmbuf_free(txq[i]);
	}
}

/* Weak so test programs that #include this file without dp.c link; the
 * forwarder's strong definition lives in dp.c. */
__attribute__((weak)) volatile sig_atomic_t fwd_stats_req;

/* One-shot stats dump (SIGUSR1 -> fwd_stats_req, read by the worker). */
static void
dpd_stats_dump(struct dpdk_priv *d, FILE *f)
{
	/* M3: aggregate the per-worker counters into one total (the SIGUSR1
	 * stats request may be answered by any worker). */
	uint64_t rx = 0, tx = 0, esp = 0, ike = 0, drop = 0;
	uint64_t dr[DR_NUM];
	memset(dr, 0, sizeof(dr));
	for (int i = 0; d->w && i < d->nworkers; i++) {
		struct dp_worker *w = &d->w[i];
		rx += w->n_rx; tx += w->n_tx; esp += w->n_esp;
		ike += w->n_ike; drop += w->n_drop;
		for (int r = 0; r < DR_NUM; r++)
			dr[r] += w->n_dropr[r];
	}
	fprintf(f, "r2dp-fwd: stats rx=%llu tx=%llu esp=%llu ike=%llu drop=%llu "
	    "spd_fail=%llu\n", (unsigned long long)rx, (unsigned long long)tx,
	    (unsigned long long)esp, (unsigned long long)ike,
	    (unsigned long long)drop, (unsigned long long)d->n_spd_fail);
	fprintf(f, "r2dp-fwd: drops");
	for (int r = 0; r < DR_NUM; r++)
		fprintf(f, " %s=%llu", dp_drop_name[r],
		    (unsigned long long)dr[r]);
	fprintf(f, "\n");
	fflush(f);
}

static int
worker_main(void *arg)
{
	struct dp_worker *w = arg;
	struct dpdk_priv *d = w->d;
	uint16_t port = d->port_id;
	uint64_t last_t = 0;

	fprintf(stderr, "r2dp-fwd: worker on lcore %u qid %u cqp %u, "
	    "outer=%u inner=%d\n", w->lcore, w->qid, w->cqp, port, d->inner_port);
	/* H5: register this worker as a QSBR reader so ctl can synchronize
	 * before freeing SA/SP memory.  tid = its lcore id (< RTE_MAX_LCORE). */
	{
		struct rte_ether_addr ea;
		if (rte_eth_macaddr_get(port, &ea) == 0)
			memcpy(w->our_mac, ea.addr_bytes, 6);
		if (d->inner_port >= 0 &&
		    rte_eth_macaddr_get(d->inner_port, &ea) == 0)
			memcpy(w->our_inner_mac, ea.addr_bytes, 6);
	}
	if (d->rcu) {
		rte_rcu_qsbr_thread_register(d->rcu, w->lcore);
		rte_rcu_qsbr_thread_online(d->rcu, w->lcore);
	}
	while (d->running) {
		uint64_t now = rte_rdtsc();

		worker_outer(w, port);
		if (d->inner_port >= 0)
			worker_inner(w, d->inner_port);

		/* report quiescent: ctl may now free anything read this iteration */
		if (d->rcu)
			rte_rcu_qsbr_quiescent(d->rcu, w->lcore);

		if (fwd_stats_req) {
			fwd_stats_req = 0;
			dpd_stats_dump(d, stderr);
		}
		if (!last_t)
			last_t = now;
		else if (now - last_t >= rte_get_timer_hz()) {  /* ~1s */
			fprintf(stderr,
			    "r2dp-fwd[%u]: stats rx=%llu tx=%llu esp=%llu ike=%llu drop=%llu\n",
			    w->lcore,
			    (unsigned long long)w->n_rx,
			    (unsigned long long)w->n_tx,
			    (unsigned long long)w->n_esp,
			    (unsigned long long)w->n_ike,
			    (unsigned long long)w->n_drop);
			last_t = now;
		}
	}
	if (d->rcu)
		rte_rcu_qsbr_thread_offline(d->rcu, w->lcore);
	return 0;
}

static int
dpd_start(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;
	unsigned lcore;
	int nw, i;

	if (d->port_id < 0)
		return -ENODEV;
	/* M3: one run-to-completion worker per slave lcore, each with its own
	 * RX/TX queue on both tap ports and its own cryptodev queue pair.
	 * -n clamps to RTE_MAX_LCORE-1 and to the lcores actually enabled. */
	nw = d->nworkers;
	if (nw < 1) nw = 1;
	if (nw > (int)RTE_MAX_LCORE - 1) nw = (int)RTE_MAX_LCORE - 1;
	{
		unsigned av = 0;
		for (unsigned x = rte_get_next_lcore(-1, 1, 0); x < RTE_MAX_LCORE;
		     x = rte_get_next_lcore(x, 1, 0)) av++;
		if (av == 0) {
			fprintf(stderr, "r2dp-fwd: no spare lcore for a worker "
			    "(run with -l 0,<n>, e.g. -l 0-1)\n");
			return -EAGAIN;
		}
		if (nw > (int)av) nw = (int)av;
	}
	d->nworkers = (uint16_t)nw;

	d->w = calloc((size_t)nw, sizeof(*d->w));
	if (!d->w)
		return -ENOMEM;

	lcore = rte_get_next_lcore(-1, 1, 1);
	for (i = 0; i < nw; i++) {
		if (lcore >= RTE_MAX_LCORE) {
			fprintf(stderr, "r2dp-fwd: need %d slave lcores but fewer "
			    "are enabled (run with -l 0,<n>)\n", nw);
			free(d->w); d->w = NULL; d->nworkers = 0;
			return -EAGAIN;
		}
		d->w[i].d = d;
		d->w[i].lcore = lcore;
		d->w[i].qid = (uint16_t)i;   /* its rx/tx queue on both ports */
		d->w[i].cqp = (uint16_t)i;   /* its cryptodev queue pair */
		/* w[i].nh is zeroed by calloc: no peer learned until it is */
		lcore = rte_get_next_lcore(lcore, 1, 1);
	}

	if (port_init(d, d->port_id, (uint16_t)nw) < 0)
		return -rte_errno;
	/* inner (plaintext) tap is optional: single-tap mode (interop lab,
	 * control-only) has only the outer port */
	if (d->inner_port >= 0)
		if (port_init(d, d->inner_port, (uint16_t)nw) < 0)
			fprintf(stderr, "r2dp-fwd: inner tap init failed\n");
	/* H5: QSBR so the ctl (main) thread can free SA/SP memory only after the
	 * workers have passed a grace period -- each worker reads sa_tab/sp_tab
	 * and holds session pointers across its crypto path with no lock.
	 * This DPDK has no rte_rcu_qsbr_alloc: size it, then rte_zmalloc. */
	{
		size_t rsz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
		d->rcu = rte_zmalloc("r2dp-rcu", rsz, RTE_CACHE_LINE_SIZE);
		if (!d->rcu) {
			fprintf(stderr, "r2dp-fwd: rte_rcu_qsbr alloc failed\n");
			free(d->w); d->w = NULL; d->nworkers = 0;
			return -ENOMEM;
		}
		rte_rcu_qsbr_init(d->rcu, RTE_MAX_LCORE);
	}
	d->running = 1;
	for (i = 0; i < nw; i++)
		rte_eal_remote_launch(worker_main, &d->w[i], d->w[i].lcore);
	return 0;
}

static void
dpd_stop(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;

	d->running = 0;
	for (int i = 0; d->w && i < d->nworkers; i++)
		if (d->w[i].lcore < RTE_MAX_LCORE)
			rte_eal_wait_lcore(d->w[i].lcore);
	if (d->rcu) {
		for (int i = 0; d->w && i < d->nworkers; i++)
			rte_rcu_qsbr_thread_unregister(d->rcu, d->w[i].lcore);
		rte_free(d->rcu);
		d->rcu = NULL;
	}
	free(d->w);
	d->w = NULL;
	d->nworkers = 0;
	spd_teardown(d);
}

/* ------------------------------------------------------------------ */
int
fwd_dp_dpdk_probe(struct fwd_dp *dp, int *argc, char **argv[],
    const char *sockpath, int verbose)
{
	struct dpdk_priv *d;
	uint16_t port;
	int ret;

	(void)sockpath;
	/* sa_tab[] holds struct rte_ipsec_session (64-byte aligned); calloc only
	 * guarantees natural (8-byte) alignment, which is UB (UBSan flags it in
	 * gcm_kat too).  rte_zmalloc can't be used here: this struct is allocated
	 * BEFORE rte_eal_init (no DPDK heap yet, so rte_zmalloc fails with
	 * ENOMEM and the dataplane is silently lost).  aligned_alloc from the C
	 * library gives the required alignment without the EAL heap (M3). */
	d = aligned_alloc(RTE_CACHE_LINE_SIZE, sizeof(*d));
	if (!d)
		return -ENOMEM;
	d->verbose = verbose;
	snprintf(d->tap_if, sizeof(d->tap_if), "%s",
	    getenv("R2DP_TAP_IF") ? getenv("R2DP_TAP_IF") : TAP_IF_DEFAULT);

	ret = rte_eal_init(*argc, *argv);
	if (ret < 0) {
		fprintf(stderr, "r2dp-fwd: rte_eal_init failed (%d)\n", ret);
		free(d);
		return ret;
	}
	*argc -= ret;
	*argv += ret;

	/* M3: worker count (from ctl.dp.nworkers, set by -n), default 1,
	 * clamped to the slave lcores actually enabled and to RTE_MAX_LCORE-1.
	 * This sizes the NIC and crypto queue-pair counts below; dpd_start
	 * re-derives the same clamp on the way to launching the workers. */
	{
		int nw = dp->nworkers;
		if (nw < 1) nw = 1;
		if (nw > (int)RTE_MAX_LCORE - 1) nw = (int)RTE_MAX_LCORE - 1;
		unsigned av = 0;
		for (unsigned x = rte_get_next_lcore(-1, 1, 0); x < RTE_MAX_LCORE;
		     x = rte_get_next_lcore(x, 1, 0)) av++;
		if (av && nw > (int)av) nw = (int)av;
		d->nworkers = (uint16_t)nw;
	}

	d->pool = rte_pktmbuf_pool_create("r2dp_pool", MEMPOOL_SIZE, MEMPOOL_CACHE,
	    0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	if (!d->pool) {
		fprintf(stderr, "r2dp-fwd: mbuf pool failed: %s\n", rte_strerror(rte_errno));
		free(d);
		return -ENOMEM;
	}

	/* Prefer the AES-NI IPSec-MB pipe PMD (the same AES-NI instructions the
	 * kernel XFRM dataplane uses, at multi-Gbps/core for AES-GCM), falling
	 * back to crypto_openssl when the MB PMD isn't present.  The PMD name is
	 * also overridable (R2DP_CRYPTO_DEV) for testing/other devices. */
	{
		const char *want = getenv("R2DP_CRYPTO_DEV") ? getenv("R2DP_CRYPTO_DEV")
		    : "crypto_aesni_mb0";
		ret = rte_cryptodev_get_dev_id(want);
		if (ret >= 0) {
			d->cdev_name_sel = want;
		} else {
			ret = rte_cryptodev_get_dev_id("crypto_aesni_mb");
			if (ret >= 0)
				d->cdev_name_sel = "crypto_aesni_mb";
		}
		if (ret < 0) {
			ret = rte_cryptodev_get_dev_id("crypto_openssl0");
			if (ret >= 0)
				d->cdev_name_sel = "crypto_openssl0";
		}
		if (ret < 0) {
			ret = rte_cryptodev_get_dev_id("crypto_openssl");
			if (ret >= 0)
				d->cdev_name_sel = "crypto_openssl";
		}
	}
	if (ret >= 0) {
		d->cdev_id = (uint8_t)ret;
		rte_cryptodev_info_get(d->cdev_id, &d->cdev_info);
		d->have_cdev = 1;
		/* configure + start the crypto device with one qp */
		struct rte_cryptodev_config cconf;
		struct rte_cryptodev_qp_conf qconf;
		memset(&cconf, 0, sizeof(cconf));
		cconf.socket_id = SOCKET_ID_ANY;
		cconf.nb_queue_pairs = d->nworkers;   /* M3: one qp per worker */
		cconf.ff_disable = 0;
		if (rte_cryptodev_configure(d->cdev_id, &cconf) < 0) {
			fprintf(stderr, "r2dp-fwd: cryptodev configure failed\n");
			d->have_cdev = 0;
		} else {
			memset(&qconf, 0, sizeof(qconf));
			qconf.nb_descriptors = 2048;
			int qok = 1;
			for (uint16_t q = 0; q < d->nworkers && qok; q++)
				if (rte_cryptodev_queue_pair_setup(d->cdev_id, q,
				    &qconf, SOCKET_ID_ANY) < 0) {
					fprintf(stderr,
					    "r2dp-fwd: cryptodev qp %u setup failed\n", q);
					qok = 0;
				}
			if (qok && rte_cryptodev_start(d->cdev_id) < 0)
				fprintf(stderr, "r2dp-fwd: cryptodev start failed\n");
		}
		if (d->have_cdev) {
			/* crypto session + op mempools */
			d->sess_mp = rte_cryptodev_sym_session_pool_create(
			    "r2dp_sess", MAX_SA,
			    rte_cryptodev_sym_get_private_session_size(d->cdev_id),
			    0, 0, SOCKET_ID_ANY);
			if (!d->sess_mp)
				fprintf(stderr, "r2dp-fwd: sess pool failed\n");
			d->cop_mp = rte_crypto_op_pool_create(
			    "r2dp_cop", RTE_CRYPTO_OP_TYPE_SYMMETRIC, MAX_SA, 0,
			    sizeof(struct rte_crypto_op) +
			      sizeof(struct rte_crypto_sym_op) +
			      R2DP_GCM_IV_LEN,
			    SOCKET_ID_ANY);
			if (!d->cop_mp)
				fprintf(stderr, "r2dp-fwd: crypto-op pool failed\n");
		}
	} else {
		fprintf(stderr, "r2dp-fwd: warning: no crypto device; add "
		    "--vdev crypto_openssl0 for AES-GCM\n");
	}

	{
		struct rte_ipsec_sad_conf conf;

		memset(&conf, 0, sizeof(conf));
		conf.socket_id = SOCKET_ID_ANY;
		/* Only the SPI_DIP key flavor is used (inbound ESP lookup).  Leave
		 * the other table types unsized (0) so the SAD doesn't preallocate
		 * SPI_ONLY / SPI_DIP_SIP tables we never query. */
		conf.max_sa[RTE_IPSEC_SAD_SPI_DIP] = MAX_SA;
		conf.flags = RTE_IPSEC_SAD_FLAG_RW_CONCURRENCY;
		d->sad = rte_ipsec_sad_create("r2dp_sad", &conf);
		if (!d->sad) {
			fprintf(stderr, "r2dp-fwd: sad create failed: %s\n",
			    rte_strerror(rte_errno));
			free(d);
			return -ENOMEM;
		}
	}

	rte_spinlock_init(&d->lock);

	d->port_id = -1;
	d->inner_port = -1;
	RTE_ETH_FOREACH_DEV(port) {
		struct rte_eth_dev_info di;
		if (rte_eth_dev_info_get(port, &di) == 0 &&
		    strstr(di.driver_name, "tap")) {
			if (d->port_id < 0) {
				d->port_id = port;                /* outer = ESP side */
			} else if (d->inner_port < 0) {
				d->inner_port = port;             /* inner = plaintext side */
			}
		}
	}
	if (d->port_id < 0) {
		fprintf(stderr, "r2dp-fwd: no tap port found "
		    "(add --vdev=net_tap0,iface=r2dp-tap)\n");
		return -ENODEV;
	}

	dp->priv = d;
	/* wire the vtable: caps/sa/sp plus the worker start/stop */
	dpdk_ops.caps   = dpdk_caps;
	dpdk_ops.sa_add = dpd_sa_add;
	dpdk_ops.sa_bytes = dpd_sa_bytes;
	dpdk_ops.sp_add = dpd_sp_add;
	dpdk_ops.sp_del = dpd_sp_del;
	dpdk_ops.start  = dpd_start;
	dpdk_ops.stop   = dpd_stop;
	dp->ops = &dpdk_ops;
	if (dp->ops->caps)
		dp->ops->caps(dp);
	if (dp->ops->start)
		dp->ops->start(dp);   /* bring up the worker + port */
	fprintf(stderr, "r2dp-fwd: DPDK dataplane ready (port=%d cdev=%d cdev_name=%s sad=%p)\n",
	    d->port_id, d->cdev_id, d->cdev_name_sel ? d->cdev_name_sel : "none",
	    (void *)d->sad);
	return 0;
}

#endif /* R2DP_HAVE_DPDK */

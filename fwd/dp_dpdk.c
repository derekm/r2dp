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

#include "r2dp/client.h"
#include "dp.h"
#include "ctl.h"
#include "dp_gcm.h"

#define MEMPOOL_CACHE 256
#define MEMPOOL_SIZE  16384
#define MAX_SA        FWD_MAXSA
#define NB_RX_QUEUE   1
#define NB_TX_QUEUE   1
#define BURST_SZ      128
#define TAP_IF_DEFAULT "r2dp-tap"

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
};

/* SPD entry mirror for the egress (outbound) worker: populated by dpd_sp_add/
 * dpd_sp_del so worker_inner can select a policy without touching ctl.  M1:
 * linear, exact/prefix selector match on (dir=OUT, sel_src/sel_dst, proto). */
struct dp_sp_ent {
	uint8_t  used;
	struct r2dp_sp sp;
};

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
	int                 verbose;
	char                tap_if[IFNAMSIZ];
	volatile int        running;
	unsigned            worker_lcore;
	/* per-queue counters for the worker (single rx/tx queue) */
	uint64_t            n_rx, n_tx, n_esp, n_ike, n_drop;
};

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

	(void)keylen;
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
	/* tunnel endpoints: addr4_to_u32 memcpy's rsa->dst.addr[0..4], raw wire
	 * order; match that exactly for endpoint selection (H3). */
	memcpy(&ds->dsta, &rsa->dst.addr[0], 4);
	memcpy(&ds->srca, &rsa->src.addr[0], 4);
	ds->used = 1;
	return 0;
}

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

	ds->used = 0;             /* unlink from worker lookups */
	if (inbound) {
		memset(&keyv, 0, sizeof(keyv));
		keyv.v4.spi = ds->spi;
		keyv.v4.dip = ds->dip;
		rte_ipsec_sad_del(d->sad, &keyv, RTE_IPSEC_SAD_SPI_DIP);
	}
	if (d->rcu)
		rte_rcu_qsbr_synchronize(d->rcu, d->worker_lcore);
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
		d->sa_tab[newidx] = scratch;
	}
	d->sa_tab[newidx].spi = ntohl(rsa->spi);
	d->sa_tab[newidx].proto = rsa->proto;
	d->sa_tab[newidx].reqid = rsa->reqid;
	d->sa_tab[newidx].dip = dip;
	d->sa_tab[newidx].inbound = inbound;
	d->sa_tab[newidx].natt = rsa->natt_type;
	/* publish last: the worker only proceeds past `used` == 1 */
	d->sa_tab[newidx].used = 1;

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
	d->sa_tab[idx].inbound = 1;
	d->sa_tab[idx].dip = dip;
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
	int slot = -1;

	if (!sp->slid)
		return -EINVAL;
	rte_spinlock_lock(&d->lock);
	for (int i = 0; i < MAX_SA; i++) {
		if (d->sp_tab[i].used) {
			if (d->sp_tab[i].sp.slid == sp->slid) { slot = i; break; }
		} else if (slot < 0)
			slot = i;
	}
	if (slot < 0) { rte_spinlock_unlock(&d->lock); return -ENOSPC; }
	d->sp_tab[slot].used = 1;
	d->sp_tab[slot].sp = *sp;   /* keep a copy for egress selector lookup */
	rte_spinlock_unlock(&d->lock);
	return 0;
}

static int
dpd_sp_del(struct fwd_dp *dp, const struct r2dp_sp *sp)
{
	struct dpdk_priv *d = dp->priv;

	rte_spinlock_lock(&d->lock);
	for (int i = 0; i < MAX_SA; i++) {
		if (d->sp_tab[i].used && d->sp_tab[i].sp.slid == sp->slid) {
			d->sp_tab[i].used = 0;
			break;
		}
	}
	rte_spinlock_unlock(&d->lock);
	return 0;
}

/* dataplane vtable (process-static so it outlives the probe).  Not const:
 * the .caps callback fills dp->ops->caps_bits_* in place. */
static struct fwd_dp_ops dpdk_ops;

/* ------------------------------------------------------------------ */
/* M1 packet path: run-to-completion on one lcore.  rx from the tap port,
 * classify, and tx back (the M1 topology is a TAP bridged to a kernel
 * interface; ESP is later processed, non-ESP IKE/ARP rides the exception
 * path -- both re-emit on the same port so the kernel sees them). */
static int
port_init(struct dpdk_priv *d, uint16_t port)
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

	uint16_t nrxq = NB_RX_QUEUE, ntxq = NB_TX_QUEUE;
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
static int in_inner_ok(struct dpdk_priv *d, uint32_t dip, struct rte_mbuf *mb);
static uint16_t
esp_inbound(struct dpdk_priv *d, struct rte_mbuf *bufs[], uint16_t nr,
    struct rte_mbuf *out[], uint16_t *nout)
{
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
		d->n_drop++;
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
		for (uint32_t i = 0; i < nk; i++)
			rte_pktmbuf_free(pm[i]);
		if (nout) *nout = 0;
		return nk;
	}

	/* per matched packet: prepare -> enqueue -> dequeue -> process */
	struct rte_crypto_op *cop[1];
	/* DIP each packet was keyed/looked-up under, for the IN-selector check */
	uint32_t p_dip[BURST_SZ];
	for (uint32_t i = 0; i < nk; i++)
		p_dip[i] = kkey[i].v4.dip;
	for (uint32_t i = 0; i < nk; i++) {
		if (sas[i] == NULL) {
			if (d->verbose)
				fprintf(stderr, "r2dp-fwd: esp sas[%u]=NULL\n", i);
			rte_pktmbuf_free(pm[i]);   /* partial match: drop */
			continue;
		}
		struct rte_ipsec_session *ss = sas[i];
		cop[0] = rte_crypto_op_alloc(d->cop_mp, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
		if (cop[0] == NULL) {
			/* pool exhausted: drop the packet, don't leak it */
			rte_pktmbuf_free(pm[i]);
			continue;
		}
		rte_crypto_op_attach_sym_session(cop[0], ss->crypto.ses);
		if (d->verbose)
			fprintf(stderr,
			    "r2dp-fwd: pre-prepare pkt_len=%u data_len=%u data_off=%u "
			    "l2=%u l3=%u\n",
			    (unsigned)rte_pktmbuf_pkt_len(pm[i]),
			    (unsigned)rte_pktmbuf_data_len(pm[i]),
			    (unsigned)rte_pktmbuf_headroom(pm[i]),
			    (unsigned)pm[i]->l2_len, (unsigned)pm[i]->l3_len);
		uint16_t np = rte_ipsec_pkt_crypto_prepare(ss, &pm[i], cop, 1);
		if (d->verbose) {
			uint8_t *b = rte_pktmbuf_mtod(pm[i], uint8_t *);
			fprintf(stderr,
			    "r2dp-fwd: post-prepare pkt=%u len=%u data.off=%u "
			    "data.len=%u msrc=%p aadoff=%ld ivec=%02x%02x%02x%02x%02x%02x%02x%02x\n",
			    (unsigned)rte_pktmbuf_pkt_len(pm[i]),
			    (unsigned)rte_pktmbuf_data_len(pm[i]),
			    (unsigned)cop[0]->sym->aead.data.offset,
			    (unsigned)cop[0]->sym->aead.data.length,
			    (void *)cop[0]->sym->m_src,
			    (long)((uint8_t *)cop[0]->sym->aead.aad.data - b),
			    b[20], b[21], b[22], b[23], b[24], b[25], b[26], b[27]);
		fprintf(stderr, "r2dp-fwd: sa_type=%u\n",
		    (unsigned)rte_ipsec_sa_type(ss->sa));
	}
	if (np == 0) {
		rte_crypto_op_free(cop[0]);
		rte_pktmbuf_free(pm[i]);
		continue;
	}
	if (d->verbose) {
			uint8_t *b = rte_pktmbuf_mtod(pm[i], uint8_t *);
			uint32_t pl = rte_pktmbuf_pkt_len(pm[i]);
			fprintf(stderr,
			    "r2dp-fwd: esp pkt=%u b20=", pl);
			for (int z = 0; z < 24 && z < (int)pl; z++)
				fprintf(stderr, "%02x", b[z]);
			fprintf(stderr, "\n");
		}
		uint16_t enq = rte_cryptodev_enqueue_burst(d->cdev_id, 0, cop, np);
		if (d->verbose)
			fprintf(stderr,
			    "r2dp-fwd: esp crypto np=%u enq=%u st=%u\n",
			    np, enq, (enq && cop[0]->status) ? cop[0]->status : 0);
		uint16_t dq = enq ?
		    rte_cryptodev_dequeue_burst(d->cdev_id, 0, cop, enq) : 0;
		/* CPU-crypto path is synchronous (dq == enq).  An enqueue failure
		 * (enq==0) or async PMD with ops left in flight (dq < enq) means we
		 * don't own every op yet: refund only what completed, drop the
		 * packet, never free an mbuf the device still holds. */
		if (!enq) {
			for (uint16_t k = 0; k < np; k++)
				rte_crypto_op_free(cop[k]);
			rte_pktmbuf_free(pm[i]);
			continue;
		}
		/* Packet i is the one due back from crypto.  rte_ipsec_pkt_process
		 * on dq (==1 here) leaves the DECRYPTED inner packet in pm[i];
		 * forward it.  On any failure drop it. */
		if (dq >= 1) {
			uint16_t proc = rte_ipsec_pkt_process(ss, &pm[i], 1);
			if (d->verbose) {
				uint8_t *bb = rte_pktmbuf_mtod(pm[i], uint8_t *);
				fprintf(stderr,
				    "r2dp-fwd: post-proc proc=%u pkt=%u ol=%08llx "
				    "b0=%02x%02x%02x%02x%02x%02x%02x%02x\n",
				    proc, (unsigned)rte_pktmbuf_pkt_len(pm[i]),
				    (unsigned long long)pm[i]->ol_flags,
				    bb[0],bb[1],bb[2],bb[3],bb[4],bb[5],bb[6],bb[7]);
			}
			/* processed packets have the inner (cleartext) frame.  D8:
			 * after a successful decrypt, apply the RFC 4301 s5.2 IN
			 * selector check and trim to the inner IP length; drop on
			 * mismatch/spoof. */
			if (proc == 1 && out && no < BURST_SZ &&
			    in_inner_ok(d, p_dip[i], pm[i]))
				out[no++] = pm[i];
			else {
				if (proc == 1 && d->verbose)
					fprintf(stderr, "r2dp-fwd: inner SEL reject\n");
				d->n_drop++;
				rte_pktmbuf_free(pm[i]);
			}
		} else {
			/* op still in flight (async): drop the packet, leave cop. */
			d->n_drop += dq == 0 ? 1 : 0;
		}
		/* refund the ops that actually came back */
		for (uint16_t k = 0; k < dq; k++)
			rte_crypto_op_free(cop[k]);
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
		if (!ds->used || !ds->inbound)
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

/* Match addr bytes against a deprecated-free selector prefix (pref 0..32). */
static int
sel_match(const struct r2dp_addr *sel, uint8_t pref, const uint8_t *ip)
{
	int nbytes;

	if (sel->family != R2DP_AF_INET4)
		return 0;
	if (sel->port)
		return 0;   /* M1: IP-level tunnel policies carry no port */
	nbytes = pref / 8;
	if (pref % 8)
		nbytes++;          /* cover the partial last byte */
	if (nbytes > 4) nbytes = 4;
	for (int i = 0; i + 1 < nbytes; i++)
		if (sel->addr[i] != ip[i])
			return 0;
	if (nbytes > 0) {
		if (pref % 8) {
			uint8_t hi = (uint8_t)(pref % 8);
			if ((sel->addr[nbytes - 1] >> (8 - hi)) !=
			    (ip[nbytes - 1] >> (8 - hi)))
				return 0;
		} else if (sel->addr[nbytes - 1] != ip[nbytes - 1])
			return 0;
	}
	return 1;
}

/* D8 (RFC 4301 s5.2): verify a decrypted inner packet against the IN policy
 * for the tunnel it arrived under.  Find the IN-PROTECT SP whose tunnel dest
 * is `dip`; its sel_src/sel_dst say which inner addresses the peer may claim.
 * If no IN policy is installed for this tunnel the packet is accepted (a peer
 * we accepted an SA from is at least past the ESP ICV); if one exists, the
 * inner src/dst must match its selector or we drop (a peer with a valid SA
 * must not be able to inject arbitrary inner addresses).  Also trims the
 * inner packet to IP total_length (no Ethernet padding smuggled into ESP). */
static int
in_inner_ok(struct dpdk_priv *d, uint32_t dip, struct rte_mbuf *mb)
{
	struct rte_ipv4_hdr *ip;
	uint8_t ihl;
	uint16_t iplen, cur;

	if (rte_pktmbuf_pkt_len(mb) < sizeof(struct rte_ipv4_hdr))
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

	for (int i = 0; i < MAX_SA; i++) {
		const struct dp_sp_ent *e = &d->sp_tab[i];
		const struct r2dp_sp *sp;
		uint32_t td;
		if (!e->used)
			continue;
		sp = &e->sp;
		if (sp->dir != R2DP_DIR_IN || sp->action != R2DP_ACT_PROTECT)
			continue;
		memcpy(&td, &sp->tun_dst.addr[0], 4);
		if (td != dip)
			continue;   /* not the tunnel this packet came in on */
		/* this tunnel's IN policy: inner src/dst must match its selector */
		if (!sel_match(&sp->sel_src, sp->pref_src,
		    (const uint8_t *)(&ip->src_addr)))
			return 0;
		if (!sel_match(&sp->sel_dst, sp->pref_dst,
		    (const uint8_t *)(&ip->dst_addr)))
			return 0;
		return 1;
	}
	return 1;   /* no IN policy installed for this tunnel: accept */
}

/* Find the EGRESS SA for this OUT policy.  racoon2 sends reqid=0 for every
 * SP and SA, so reqid alone would collapse all tunnels onto the first
 * outbound SA (H3).  Prefer an exact tunnel-endpoint match (policy tun_src/
 * tun_dst == SA src/dst); among endpoint matches prefer a real (nonzero)
 * reqid when the policy carries one, else the last matching slot. */
static struct dp_sa *
sa_by_policy(struct dpdk_priv *d, const struct r2dp_sp *sp)
{
	struct dp_sa *endpoint = NULL, *last_match = NULL;
	uint32_t ts, td;
	int i;

	memcpy(&ts, &sp->tun_src.addr[0], 4);
	memcpy(&td, &sp->tun_dst.addr[0], 4);
	for (i = 0; i < MAX_SA; i++) {
		struct dp_sa *ds = &d->sa_tab[i];
		if (!ds->used || ds->inbound)
			continue;
		if (ds->srca != ts || ds->dsta != td)
			continue;
		/* exact endpoint match */
		if (sp->reqid && ds->reqid == sp->reqid)
			return ds;                 /* best: endpoint + real reqid */
		last_match = ds;
		if (!ds->reqid)
			endpoint = ds;             /* fallback: endpoint only */
	}
	return endpoint ? endpoint : last_match;
}

/* Find the OUT policy that (longest-prefix) matches this inner IPv4 packet.
 * Returns the matched sp (or NULL); sets *sa to the reqid-linked EGRESS SA. */
static const struct r2dp_sp *
sp_match_out(struct dpdk_priv *d, const struct rte_ipv4_hdr *ip,
    struct dp_sa **sa)
{
	const struct r2dp_sp *best = NULL;
	int bestpref = -1;

	for (int i = 0; i < MAX_SA; i++) {
		const struct dp_sp_ent *e = &d->sp_tab[i];
		const struct r2dp_sp *sp;
		if (!e->used)
			continue;
		sp = &e->sp;
		if (sp->dir != R2DP_DIR_OUT)
			continue;
		/* match any action so DISCARD/BYPASS policies can override a
		 * PROTECT (M6); esp_outbound then enforces the disposition */
		if (sp->ul_proto != R2DP_PROTO_ANY &&
		    sp->ul_proto != ip->next_proto_id)
			continue;
		if (!sel_match(&sp->sel_src, sp->pref_src,
		    (const uint8_t *)&ip->src_addr))
			continue;
		if (!sel_match(&sp->sel_dst, sp->pref_dst,
		    (const uint8_t *)&ip->dst_addr))
			continue;
		/* prefer the most specific policy for this flow */
		if ((int)(sp->pref_src + sp->pref_dst) > bestpref) {
			bestpref = sp->pref_src + sp->pref_dst;
			best = sp;
		}
	}
	*sa = (best && best->action == R2DP_ACT_PROTECT) ?
	    sa_by_policy(d, best) : NULL;
	return best;
}

/* Outbound ESP: take inner IPv4 plaintext (L2 already stripped, l2_len=0),
 * look up the OUT policy + EGRESS SA, run rte_ipsec EGRESS encrypt, and write
 * the resulting ESP datagram (outer IP + ESP, L2 NOT yet re-added) into `out`.
 * Non-protected packets are left alone (returned as unchanged bypass). */
static void
esp_outbound(struct dpdk_priv *d, struct rte_mbuf *bufs[], uint16_t nr,
    struct rte_mbuf *out[], uint16_t *nout, uint16_t *nbypass)
{
	uint16_t no = 0, nb = 0;

	for (uint16_t i = 0; i < nr; i++) {
		struct dp_sa *ds;
		const struct r2dp_sp *sp;
		uint8_t ihl;
		struct rte_ipv4_hdr *ip, *lip;
		struct rte_crypto_op *cop;
		uint16_t np, enq, dq, proc;

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
		sp = sp_match_out(d, ip, &ds);
		if (!sp) { nb++; continue; }   /* no matching OUT policy: bypass */

		/* A matched policy decides the disposition (H2, RFC 4301 5.1):
		 * DISCARD always drops; PROTECT with no SA drops (fail-closed, the
		 * SA must exist before we protect); only BYPASS forwards clear. */
		if (sp->action == R2DP_ACT_DISCARD)
			goto drop;
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
		if (ihl < 20 || ihl > (uint8_t)rte_pktmbuf_data_len(bufs[i]))
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

		cop = rte_crypto_op_alloc(d->cop_mp, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
		if (!cop) goto drop;
		rte_crypto_op_attach_sym_session(cop, ds->sess.crypto.ses);
		np = rte_ipsec_pkt_crypto_prepare(&ds->sess, &bufs[i], &cop, 1);
		if (np == 0) { rte_crypto_op_free(cop); goto drop; }
		enq = rte_cryptodev_enqueue_burst(d->cdev_id, 0, &cop, np);
		if (enq == 0) { rte_crypto_op_free(cop); goto drop; }
		dq = rte_cryptodev_dequeue_burst(d->cdev_id, 0, &cop, enq);
		/* CPU-crypto path is synchronous (dq == enq); a PMD that reports
		 * dq < enq means ops still in flight and this single-op loop does
		 * not own them yet -- free only what came back, drop the rest. */
		if (d->verbose)
			fprintf(stderr, "r2dp-fwd: egress crypto np=%u enq=%u dq=%u st=%u\n",
			    np, enq, dq, (dq && cop->status) ? cop->status : 0);
		if (dq == 0) { rte_crypto_op_free(cop); goto drop; }
		proc = rte_ipsec_pkt_process(&ds->sess, &bufs[i], dq);
		rte_crypto_op_free(cop);
		if (proc == 1 && out && no < BURST_SZ) {
			/* bufs[i] is now the ESP datagram (outer IP + ESP).  librte's
			 * outbound tunnel prepare only patches total_length/packet_id;
			 * it leaves hdr_checksum=0, which every real peer drops
			 * (ip_rcv -> InHdrErrors).  Compute it here (H1). */
			struct rte_ipv4_hdr *oip =
			    rte_pktmbuf_mtod(bufs[i], struct rte_ipv4_hdr *);
			if ((oip->version_ihl >> 4) == 4) {
				oip->hdr_checksum = 0;
				oip->hdr_checksum = rte_ipv4_cksum(oip);
			}
			if (d->verbose) {
				uint8_t *b = rte_pktmbuf_mtod(bufs[i], uint8_t *);
				fprintf(stderr,
				    "r2dp-fwd: egress-proc proc=%u pkt=%u b0=%02x%02x%02x%02x%02x%02x%02x%02x\n",
				    proc, (unsigned)rte_pktmbuf_pkt_len(bufs[i]),
				    b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]);
			}
			d->n_esp++;
			out[no++] = bufs[i];
			bufs[i] = NULL;      /* consumed: mark for caller */
			continue;
		}
		/* Crypto/decrypt failed or the processed packet was invalid: drop. */
		goto drop;
drop:
		/* Single drop path: never forward cleartext after a policy matched,
		 * and never leak the mbuf (H4).  Count and mark the slot NULL so
		 * worker_inner does not forward or free it again. */
		d->n_drop++;
		rte_pktmbuf_free(bufs[i]);
		bufs[i] = NULL;
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
static void
worker_outer(struct dpdk_priv *d, int port)
{
	struct rte_mbuf *bufs[BURST_SZ];
	struct rte_mbuf *esp[BURST_SZ], *exc[BURST_SZ];
	uint16_t nr = rte_eth_rx_burst(port, 0, bufs, BURST_SZ);

	if (nr == 0)
		return;
	d->n_rx += nr;
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
		if (is_esp(bufs[i]) || is_nat_esp(d, bufs[i])) {
			d->n_esp++;
			esp[nesp++] = bufs[i];
		} else {
			exc[nex++] = bufs[i];
		}
	}

	if (nesp) {
		struct rte_mbuf *dec[BURST_SZ];
		uint16_t ndec = 0;
		esp_inbound(d, esp, nesp, dec, &ndec);
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
					rte_pktmbuf_free(dec[i]);
					dec[i] = NULL;
					continue;
				}
				eh = rte_pktmbuf_mtod(dec[i],
				    struct rte_ether_hdr *);
				memset(eh->dst_addr.addr_bytes, 0xff, 6);
				memset(eh->src_addr.addr_bytes, 0x00, 6);
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
			uint16_t sent = rte_eth_tx_burst(to, 0, txq, ntx);
			d->n_tx += sent;
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
				d->n_drop++;
		}
		if (nf) {
			if (is_udp(fwd[0]))
				d->n_ike += nf;   /* IKE */
			uint16_t sent = rte_eth_tx_burst(to, 0, fwd, nf);
			d->n_tx += sent;
			d->n_drop += nf - sent;
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
worker_inner(struct dpdk_priv *d, int port)
{
	struct rte_mbuf *bufs[BURST_SZ];
	uint16_t nr = rte_eth_rx_burst(port, 0, bufs, BURST_SZ);

	if (nr == 0)
		return;
	d->n_rx += nr;

	/* 1. classify: ESP here is anomalous -> drop; non-ESP may be protected
	 *    (encrypt) or unprotected (IKE/ARP -> exception path). */
	struct rte_mbuf *nonesp[BURST_SZ];
	uint16_t nnon = 0;
	for (uint16_t i = 0; i < nr; i++) {
		if (is_esp(bufs[i]))
			rte_pktmbuf_free(bufs[i]);
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
	esp_outbound(d, nonesp, nnon, esp_out, &nout, &nby);

	/* 3. prepend L2 to the ESP datagrams and tx to the outer (peer) tap */
	if (nout) {
		uint16_t ntx = 0;
		struct rte_mbuf *txq[BURST_SZ];
		uint16_t to = (d->port_id >= 0) ? d->port_id : port;
		for (uint16_t i = 0; i < nout; i++) {
			struct rte_ether_hdr *eh;
			char *h = rte_pktmbuf_prepend(esp_out[i], RTE_ETHER_HDR_LEN);
			if (!h) { rte_pktmbuf_free(esp_out[i]); continue; }
			eh = rte_pktmbuf_mtod(esp_out[i], struct rte_ether_hdr *);
			memset(eh->dst_addr.addr_bytes, 0xff, 6);
			memset(eh->src_addr.addr_bytes, 0x00, 6);
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
		uint16_t sent = rte_eth_tx_burst(to, 0, txq, ntx);
		d->n_tx += sent;
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
		for (uint16_t i = 0; i < nnon; i++) {
			int consumed = 0;
			if (nonesp[i] == NULL) { continue; }   /* consumed by esp_outbound */
			for (uint16_t j = 0; j < nout; j++)
				if (nonesp[i] == esp_out[j]) { consumed = 1; break; }
			if (!consumed)
				txq[ntx++] = nonesp[i];
		}
		if (is_udp(txq[0]))
			d->n_ike += ntx;
		uint16_t sent = rte_eth_tx_burst(to, 0, txq, ntx);
		d->n_tx += sent;
		d->n_drop += ntx - sent;
		for (uint16_t i = sent; i < ntx; i++)
			rte_pktmbuf_free(txq[i]);
	}
}

static int
worker_main(void *arg)
{
	struct dpdk_priv *d = arg;
	uint16_t port = d->port_id;
	uint64_t last_t = 0;

	fprintf(stderr, "r2dp-fwd: worker on lcore %u, outer=%u inner=%d\n",
	    rte_lcore_id(), port, d->inner_port);
	/* H5: register this worker as a QSBR reader so ctl can synchronize
	 * before freeing SA/SP memory.  tid = its lcore id (< RTE_MAX_LCORE). */
	if (d->rcu) {
		rte_rcu_qsbr_thread_register(d->rcu, d->worker_lcore);
		rte_rcu_qsbr_thread_online(d->rcu, d->worker_lcore);
	}
	while (d->running) {
		uint64_t now = rte_rdtsc();

		worker_outer(d, port);
		if (d->inner_port >= 0)
			worker_inner(d, d->inner_port);

		/* report quiescent: ctl may now free anything read this iteration */
		if (d->rcu)
			rte_rcu_qsbr_quiescent(d->rcu, d->worker_lcore);

		if (!last_t)
			last_t = now;
		else if (now - last_t >= rte_get_timer_hz()) {  /* ~1s */
			fprintf(stderr,
			    "r2dp-fwd: stats rx=%llu tx=%llu esp=%llu ike=%llu drop=%llu\n",
			    (unsigned long long)d->n_rx,
			    (unsigned long long)d->n_tx,
			    (unsigned long long)d->n_esp,
			    (unsigned long long)d->n_ike,
			    (unsigned long long)d->n_drop);
			last_t = now;
		}
	}
	if (d->rcu)
		rte_rcu_qsbr_thread_offline(d->rcu, d->worker_lcore);
	return 0;
}

static int
dpd_start(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;
	unsigned lcore;

	if (d->port_id < 0)
		return -ENODEV;
	/* pick a slave lcore, skipping the main (calling) lcore */
	lcore = rte_get_next_lcore(-1, 1, 1);
	if (lcore >= RTE_MAX_LCORE) {
		fprintf(stderr, "r2dp-fwd: no spare lcore for the worker "
		    "(run with -l 0,<n>, e.g. -l 0-1)\n");
		return -EAGAIN;
	}
	if (port_init(d, d->port_id) < 0)
		return -rte_errno;
	/* inner (plaintext) tap is optional: single-tap mode (interop lab,
	 * control-only) has only the outer port */
	if (d->inner_port >= 0)
		if (port_init(d, d->inner_port) < 0)
			fprintf(stderr, "r2dp-fwd: inner tap init failed\n");
	/* H5: QSBR so the ctl (main) thread can free SA/SP memory only after the
	 * worker has passed a grace period -- the worker reads sa_tab/sp_tab and
	 * holds session pointers across its crypto path with no lock, so a
	 * synchronize here prevents a UAF when ctl deletes/rekeys under load.
	 * This DPDK has no rte_rcu_qsbr_alloc: size it, then rte_zmalloc. */
	{
		size_t rsz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
		d->rcu = rte_zmalloc("r2dp-rcu", rsz, RTE_CACHE_LINE_SIZE);
		if (!d->rcu) {
			fprintf(stderr, "r2dp-fwd: rte_rcu_qsbr alloc failed\n");
			return -ENOMEM;
		}
		rte_rcu_qsbr_init(d->rcu, RTE_MAX_LCORE);
	}
	d->running = 1;
	d->worker_lcore = lcore;
	rte_eal_remote_launch(worker_main, d, lcore);
	return 0;
}

static void
dpd_stop(struct fwd_dp *dp)
{
	struct dpdk_priv *d = dp->priv;

	d->running = 0;
	if (d->worker_lcore < RTE_MAX_LCORE)
		rte_eal_wait_lcore(d->worker_lcore);
	if (d->rcu) {
		rte_rcu_qsbr_thread_unregister(d->rcu, d->worker_lcore);
		rte_free(d->rcu);
		d->rcu = NULL;
	}
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

	d->pool = rte_pktmbuf_pool_create("r2dp_pool", MEMPOOL_SIZE, MEMPOOL_CACHE,
	    0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	if (!d->pool) {
		fprintf(stderr, "r2dp-fwd: mbuf pool failed: %s\n", rte_strerror(rte_errno));
		free(d);
		return -ENOMEM;
	}

	ret = rte_cryptodev_get_dev_id("crypto_openssl0");
	if (ret < 0)
		ret = rte_cryptodev_get_dev_id("crypto_openssl");
	if (ret >= 0) {
		d->cdev_id = (uint8_t)ret;
		rte_cryptodev_info_get(d->cdev_id, &d->cdev_info);
		d->have_cdev = 1;
		/* configure + start the crypto device with one qp */
		struct rte_cryptodev_config cconf;
		struct rte_cryptodev_qp_conf qconf;
		memset(&cconf, 0, sizeof(cconf));
		cconf.socket_id = SOCKET_ID_ANY;
		cconf.nb_queue_pairs = 1;
		cconf.ff_disable = 0;
		if (rte_cryptodev_configure(d->cdev_id, &cconf) < 0) {
			fprintf(stderr, "r2dp-fwd: cryptodev configure failed\n");
			d->have_cdev = 0;
		} else {
			memset(&qconf, 0, sizeof(qconf));
			qconf.nb_descriptors = 2048;
			if (rte_cryptodev_queue_pair_setup(d->cdev_id, 0, &qconf,
			    SOCKET_ID_ANY) < 0)
				fprintf(stderr, "r2dp-fwd: cryptodev qp setup failed\n");
			else if (rte_cryptodev_start(d->cdev_id) < 0)
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
	dpdk_ops.sp_add = dpd_sp_add;
	dpdk_ops.sp_del = dpd_sp_del;
	dpdk_ops.start  = dpd_start;
	dpdk_ops.stop   = dpd_stop;
	dp->ops = &dpdk_ops;
	if (dp->ops->caps)
		dp->ops->caps(dp);
	if (dp->ops->start)
		dp->ops->start(dp);   /* bring up the worker + port */
	fprintf(stderr, "r2dp-fwd: DPDK dataplane ready (port=%d cdev=%d sad=%p)\n",
	    d->port_id, d->cdev_id, (void *)d->sad);
	return 0;
}

#endif /* R2DP_HAVE_DPDK */

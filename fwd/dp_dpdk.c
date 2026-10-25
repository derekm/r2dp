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

#include "r2dp/client.h"
#include "dp.h"
#include "ctl.h"

#define MEMPOOL_CACHE 256
#define MEMPOOL_SIZE  16384
#define MAX_SA        FWD_MAXSA
#define NB_RX_QUEUE   1
#define NB_TX_QUEUE   1
#define BURST_SZ      128
#define TAP_IF_DEFAULT "r2dp-tap"
/* AES-GCM standard IV is 12 bytes (RFC 4106). */
#define R2DP_GCM_IV_LEN 12

struct dp_sa {
	struct rte_ipsec_sa *sa;      /* opaque, allocated from the ipsec lib */
	struct rte_ipsec_session sess;/* ipsec session bound to the crypto dev */
	struct rte_cryptodev_sym_session *cses;   /* crypto sym session */
	uint32_t           spi;      /* host order */
	uint32_t           dip;      /* host order */
	uint8_t            proto;
	uint8_t            used;
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
	struct dp_sa        sa_tab[MAX_SA];
	int                 verbose;
	char                tap_if[IFNAMSIZ];
	volatile int        running;
	unsigned            worker_lcore;
	/* per-queue counters for the worker (single rx/tx queue) */
	uint64_t            n_rx, n_tx, n_esp, n_ike, n_drop;
};

/* ------------------------------------------------------------------ */
static void
dpdk_caps(uint32_t enc_caps[R2DP_CAP_WORDS], uint32_t integ_caps[R2DP_CAP_WORDS])
{
	memset(enc_caps, 0, sizeof(enc_caps[0]) * R2DP_CAP_WORDS);
	memset(integ_caps, 0, sizeof(integ_caps[0]) * R2DP_CAP_WORDS);
	enc_caps[0] = (1u << R2DP_ENCR_AES_GCM_16) | (1u << R2DP_ENCR_AES_CBC);
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
 * tunnel.  AEAD key blob = cipher key (16) || salt (4) = 20 bytes (M0 f3). */
static int
dp_sa_init(struct dpdk_priv *d, struct dp_sa *ds, const struct r2dp_sa *rsa,
    const void *key, size_t keylen)
{
	struct rte_ipsec_sa_prm prm;
	struct rte_crypto_sym_xform aead, *cur;
	size_t sa_sz;
	uint32_t salt, src, dst;

	(void)keylen;
	if (rsa->mode != R2DP_MODE_TUNNEL)
		return -EOPNOTSUPP;
	if (rsa->enc != R2DP_ENCR_AES_GCM_16)
		return -EOPNOTSUPP;
	if (rsa->enckeylen != 20)
		return -EINVAL;
	if (!d->have_cdev)
		return -ENODEV;
	if (addr4_to_u32(&rsa->src, &src) < 0 ||
	    addr4_to_u32(&rsa->dst, &dst) < 0)
		return -EAFNOSUPPORT;

	memset(&prm, 0, sizeof(prm));
	memset(&aead, 0, sizeof(aead));

	memcpy(&salt, (const uint8_t *)key + 16, 4);

	aead.type = RTE_CRYPTO_SYM_XFORM_AEAD;
	aead.aead.algo = RTE_CRYPTO_AEAD_AES_GCM;
	aead.aead.key.length = 16;
	aead.aead.iv.length = R2DP_GCM_IV_LEN;
	aead.aead.digest_length = 16;
	aead.aead.aad_length = 0;
	aead.aead.key.data = (uint8_t *)key;
	cur = &aead;
	prm.crypto_xform = cur;

	prm.ipsec_xform.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
	prm.ipsec_xform.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL;
	prm.ipsec_xform.spi = ntohl(rsa->spi);
	prm.ipsec_xform.salt = salt;
	prm.ipsec_xform.options.esn = (rsa->saflags & R2DP_SAF_ESN) ? 1 : 0;
	prm.ipsec_xform.replay_win_sz = rsa->wsize ? rsa->wsize : 64;
	prm.ipsec_xform.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;

	{
		struct rte_ipv4_hdr eh;

		memset(&eh, 0, sizeof(eh));
		eh.version_ihl = 0x45;
		eh.time_to_live = 64;
		eh.next_proto_id = IPPROTO_ESP;
		memcpy(&eh.src_addr, &src, 4);
		memcpy(&eh.dst_addr, &dst, 4);
		prm.tun.hdr_len = sizeof(eh);
		prm.tun.hdr_l3_off = 0;
		prm.tun.next_proto = IPPROTO_ESP;
		prm.tun.hdr = &eh;
	}

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

	/* bind it into an rte_ipsec_session (direction set per SA later) */
	memset(&ds->sess, 0, sizeof(ds->sess));
	ds->sess.sa = ds->sa;
	ds->sess.type = RTE_SECURITY_ACTION_TYPE_CPU_CRYPTO;
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

/* ------------------------------------------------------------------ */
static int
sa_install(struct dpdk_priv *d, const struct r2dp_sa *rsa,
    const void *key, size_t keylen, int remove)
{
	union rte_ipsec_sad_key keyv;
	uint32_t dip = 0;
	int idx = -1, ret;

	if (addr4_to_u32(&rsa->dst, &dip) < 0)
		return -EAFNOSUPPORT;

	rte_spinlock_lock(&d->lock);

	if (remove) {
		for (int i = 0; i < MAX_SA; i++) {
			if (d->sa_tab[i].used && d->sa_tab[i].spi == ntohl(rsa->spi) &&
			    d->sa_tab[i].proto == rsa->proto) {
				memset(&keyv, 0, sizeof(keyv));
				keyv.v4.spi = ntohl(rsa->spi);
				keyv.v4.dip = dip;
				rte_ipsec_sad_del(d->sad, &keyv, RTE_IPSEC_SAD_SPI_DIP);
				sa_slot_free(d, &d->sa_tab[i]);
				break;
			}
		}
		rte_spinlock_unlock(&d->lock);
		return 0;
	}

	/* Upsert (SA_ADD on a larval, or SA_UPDATE on a live SA): the SAD key is
	 * (SPI, DIP), so installing a new session for the same SPI requires a
	 * del-then-add.  Find the slot holding that SPI's current session, tear it
	 * down, and reuse it -- otherwise rte_ipsec_sad_add fails (duplicate key)
	 * and the error is swallowed, leaving ctl's table on the new SA while the
	 * SAD keeps the old (review finding). */
	idx = -1;
	for (int i = 0; i < MAX_SA; i++) {
		if (d->sa_tab[i].used && d->sa_tab[i].proto == rsa->proto &&
		    d->sa_tab[i].spi == ntohl(rsa->spi)) {
			idx = i;
			break;
		}
	}
	if (idx >= 0) {
		memset(&keyv, 0, sizeof(keyv));
		keyv.v4.spi = ntohl(rsa->spi);
		keyv.v4.dip = dip;
		rte_ipsec_sad_del(d->sad, &keyv, RTE_IPSEC_SAD_SPI_DIP);
		sa_slot_free(d, &d->sa_tab[idx]);
	}

	/* index the first free slot (which may be the just-freed one) */
	idx = -1;
	for (int i = 0; i < MAX_SA; i++)
		if (!d->sa_tab[i].used) { idx = i; break; }
	if (idx < 0) {
		rte_spinlock_unlock(&d->lock);
		return -ENOSPC;
	}

	ret = dp_sa_init(d, &d->sa_tab[idx], rsa, key, keylen);
	if (ret < 0) {
		rte_spinlock_unlock(&d->lock);
		return ret;
	}

	memset(&keyv, 0, sizeof(keyv));
	keyv.v4.spi = ntohl(rsa->spi);
	keyv.v4.dip = dip;
	ret = rte_ipsec_sad_add(d->sad, &keyv, RTE_IPSEC_SAD_SPI_DIP,
	    &d->sa_tab[idx].sess);   /* SAD value = the ipsec session ptr */
	if (ret < 0) {
		if (d->sa_tab[idx].cses)
			rte_cryptodev_sym_session_free(d->cdev_id, d->sa_tab[idx].cses);
		if (d->sa_tab[idx].sa)
			rte_ipsec_sa_fini(d->sa_tab[idx].sa);
		rte_free(d->sa_tab[idx].sa);
		memset(&d->sa_tab[idx], 0, sizeof(d->sa_tab[idx]));
		rte_spinlock_unlock(&d->lock);
		return ret;
	}
	d->sa_tab[idx].dip = dip;
	rte_spinlock_unlock(&d->lock);
	return 0;
}

/* ------------------------------------------------------------------ */
static int
dpd_sa_add(struct fwd_dp *dp, int add, const struct r2dp_sa *sa,
    const void *blob, size_t blen)
{
	struct dpdk_priv *d = dp->priv;

	return sa_install(d, sa, blob, blen, !add);
}

static int
dpd_sp_add(struct fwd_dp *dp, struct r2dp_sp *sp)
{
	struct dpdk_priv *d = dp->priv;
	(void)d;
	return sp->slid ? 0 : -EINVAL;
}

static int
dpd_sp_del(struct fwd_dp *dp, const struct r2dp_sp *sp)
{
	(void)dp; (void)sp;
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
	rte_eth_dev_info_get(port, &dev_info);
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
		struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)
		    ((uint8_t *)eh + RTE_ETHER_HDR_LEN);
		struct rte_esp_hdr *es;
		uint8_t ihl;

		if (rte_pktmbuf_pkt_len(bufs[i]) < RTE_ETHER_HDR_LEN +
		    sizeof(struct rte_ipv4_hdr) + sizeof(*es))
			break;      /* too short to be inbound ESP */
		ihl = (ip->version_ihl & 0x0f) * 4;
		es = (struct rte_esp_hdr *)((uint8_t *)ip + ihl);

		bufs[i]->l2_len = RTE_ETHER_HDR_LEN;
		bufs[i]->l3_len = ihl;
		bufs[i]->ol_flags |= RTE_MBUF_F_RX_SEC_OFFLOAD;
		bufs[i]->packet_type = RTE_PTYPE_L3_IPV4;
		kkey[nk].v4.spi = ntohl(es->spi);
		/* dst_addr is network order; addr4_to_u32 (SA insert) produced the
		 * same numeric, so match it here without a second byte-swap */
		kkey[nk].v4.dip = rte_be_to_cpu_32(ip->dst_addr);
		keys[nk] = &kkey[nk];
		pm[nk] = bufs[i];
		nk++;
	}
	if (nk == 0) {
		if (nout) *nout = 0;
		return 0;
	}

	uint32_t nlook = rte_ipsec_sad_lookup(d->sad, keys, sas, nk);

	if (nlook == 0) {
		/* no SA matched -- drop the whole burst */
		for (uint32_t i = 0; i < nk; i++)
			rte_pktmbuf_free(pm[i]);
		if (nout) *nout = 0;
		return nk;
	}

	/* per matched packet: prepare -> enqueue -> dequeue -> process */
	struct rte_crypto_op *cop[1];
	for (uint32_t i = 0; i < nk; i++) {
		if (sas[i] == NULL) {
			rte_pktmbuf_free(pm[i]);   /* partial match: drop */
			continue;
		}
		struct rte_ipsec_session *ss = sas[i];
		cop[0] = rte_crypto_op_alloc(d->cop_mp, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
		if (cop[0] == NULL)
			continue;
		rte_crypto_op_attach_sym_session(cop[0], ss->crypto.ses);
		uint16_t np = rte_ipsec_pkt_crypto_prepare(ss, &pm[i], cop, 1);
		if (np == 0) {
			rte_crypto_op_free(cop[0]);
			rte_pktmbuf_free(pm[i]);
			continue;
		}
		uint16_t enq = rte_cryptodev_enqueue_burst(d->cdev_id, 0, cop, np);
		uint16_t dq = enq ?
		    rte_cryptodev_dequeue_burst(d->cdev_id, 0, cop, enq) : 0;
		/* Packet i is the one due back from crypto.  rte_ipsec_pkt_process
		 * on dq (==1 here) leaves the DECRYPTED inner packet in pm[i];
		 * forward it.  On any failure drop it. */
		if (dq == 1) {
			uint16_t proc = rte_ipsec_pkt_process(ss, &pm[i], dq);
			/* processed packets have the inner (cleartext) frame */
			if (proc == 1 && out && no < BURST_SZ)
				out[no++] = pm[i];
			else
				rte_pktmbuf_free(pm[i]);
		} else {
			rte_pktmbuf_free(pm[i]);
		}
		/* completed ops are safe to return/refund after process */
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

/* Process a burst received on the OUTER tap (ESP side): ESP -> decrypt ->
 * forward the inner (cleartext) packet out the inner tap; non-ESP (IKE, ARP)
 * is the exception path and crosses to the inner (kernel) side. */
static void
worker_outer(struct dpdk_priv *d, int port)
{
	struct rte_mbuf *bufs[BURST_SZ];
	uint16_t nr = rte_eth_rx_burst(port, 0, bufs, BURST_SZ);

	if (nr == 0)
		return;
	d->n_rx += nr;
	uint16_t np = 0;
	uint16_t nesp = 0;
	for (uint16_t i = 0; i < nr; i++) {
		if (is_esp(bufs[i])) {
			d->n_esp++;
			bufs[nesp] = bufs[i];
			nesp++;
		} else {
			np++;
		}
	}

	if (nesp) {
		struct rte_mbuf *dec[BURST_SZ];
		uint16_t ndec = 0;
		esp_inbound(d, bufs, nesp, dec, &ndec);
		if (ndec) {
			uint16_t to = (d->inner_port >= 0) ? d->inner_port : port;
			uint16_t sent = rte_eth_tx_burst(to, 0, dec, ndec);
			d->n_tx += sent;
			for (uint16_t i = sent; i < ndec; i++)
				rte_pktmbuf_free(dec[i]);
		}
	}
	/* non-ESP: exception path -> the kernel side */
	if (np) {
		struct rte_mbuf *plain[BURST_SZ];
		uint16_t nplain = 0;
		for (uint16_t i = 0; i < nr; i++) {
			if (!is_esp(bufs[i]))
				plain[nplain++] = bufs[i];
		}
		if (nplain && is_udp(plain[0]))   /* IKE */
			d->n_ike += nplain;
		uint16_t to = (d->inner_port >= 0) ? d->inner_port : port;
		uint16_t sent = rte_eth_tx_burst(to, 0, plain, nplain);
		d->n_tx += sent;
		d->n_drop += nplain - sent;
		for (uint16_t i = sent; i < nplain; i++)
			rte_pktmbuf_free(plain[i]);
	}
}

/* Process a burst received on the INNER tap (plaintext/kernel side): ESP is
 * unusual here, but non-ESP (IKE/ARP from the kernel) is the outbound
 * exception path and crosses to the outer (peer) tap.  M1 data-plane outbound
 * (encrypt inner plaintext -> ESP) is the next leg, not yet wired. */
static void
worker_inner(struct dpdk_priv *d, int port)
{
	struct rte_mbuf *bufs[BURST_SZ];
	uint16_t nr = rte_eth_rx_burst(port, 0, bufs, BURST_SZ);

	if (nr == 0)
		return;
	d->n_rx += nr;
	/* non-ESP from the kernel: exception path out to the peer */
	struct rte_mbuf *plain[BURST_SZ];
	uint16_t nplain = 0;
	for (uint16_t i = 0; i < nr; i++) {
		if (is_esp(bufs[i]))
			rte_pktmbuf_free(bufs[i]);   /* not handled in M1 outbound */
		else
			plain[nplain++] = bufs[i];
	}
	if (nplain) {
		if (is_udp(plain[0]))
			d->n_ike += nplain;
		uint16_t to = (d->port_id >= 0) ? d->port_id : port;
		uint16_t sent = rte_eth_tx_burst(to, 0, plain, nplain);
		d->n_tx += sent;
		d->n_drop += nplain - sent;
		for (uint16_t i = sent; i < nplain; i++)
			rte_pktmbuf_free(plain[i]);
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
	for (;;) {
		uint64_t now = rte_rdtsc();

		worker_outer(d, port);
		if (d->inner_port >= 0)
			worker_inner(d, d->inner_port);

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
	d = calloc(1, sizeof(*d));
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
			    0, SOCKET_ID_ANY);
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
		conf.max_sa[RTE_IPSEC_SAD_SPI_ONLY] = MAX_SA;
		conf.max_sa[RTE_IPSEC_SAD_SPI_DIP] = MAX_SA;
		conf.max_sa[RTE_IPSEC_SAD_SPI_DIP_SIP] = MAX_SA;
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
		dp->ops->caps(dp->ops->caps_bits_enc, dp->ops->caps_bits_integ);
	if (dp->ops->start)
		dp->ops->start(dp);   /* bring up the worker + port */
	fprintf(stderr, "r2dp-fwd: DPDK dataplane ready (port=%d cdev=%d sad=%p)\n",
	    d->port_id, d->cdev_id, (void *)d->sad);
	return 0;
}

#endif /* R2DP_HAVE_DPDK */

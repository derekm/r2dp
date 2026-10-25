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

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_ip.h>
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

#include "r2dp/client.h"
#include "dp.h"
#include "ctl.h"

#define MEMPOOL_CACHE 256
#define MEMPOOL_SIZE  4096
#define MAX_SA        FWD_MAXSA
#define TAP_IF_DEFAULT "r2dp-tap"
/* AES-GCM standard IV is 12 bytes (RFC 4106). */
#define R2DP_GCM_IV_LEN 12

struct dp_sa {
	struct rte_ipsec_sa *sa;      /* opaque, allocated from the ipsec lib */
	uint32_t           spi;      /* host order */
	uint32_t           dip;      /* host order */
	uint8_t            proto;
	uint8_t            used;
};

struct dpdk_priv {
	int                 port_id;
	struct rte_mempool *pool;
	struct rte_ipsec_sad *sad;
	struct rte_cryptodev_info cdev_info;
	uint8_t             cdev_id;
	int                 have_cdev;
	rte_spinlock_t      lock;
	struct dp_sa        sa_tab[MAX_SA];
	int                 verbose;
	char                tap_if[IFNAMSIZ];
};

/* ------------------------------------------------------------------ */
static void
dpdk_caps(uint32_t enc_caps[R2DP_CAP_WORDS], uint32_t integ_caps[R2DP_CAP_WORDS])
{
	memset(enc_caps, 0, sizeof(enc_caps[0]) * R2DP_CAP_WORDS);
	memset(integ_caps, 0, sizeof(integ_caps[0]) * R2DP_CAP_WORDS);
	enc_caps[0] = (1u << R2DP_ENCR_AES_GCM_16) | (1u << R2DP_ENCR_AES_CBC);
	(void)integ_caps;
}

static int
addr4_to_u32(const struct r2dp_addr *a, uint32_t *out)
{
	if (a->family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;
	memcpy(out, a->addr, 4);
	return 0;
}

/* r2dp SA -> rte_ipsec_sa.  M1: AES-GCM-16 tunnel.  AEAD key blob =
 * cipher key (16) || salt (4) = 20 bytes (M0 finding 3). */
static int
dp_sa_init(struct dp_sa *ds, const struct r2dp_sa *rsa,
    const void *key, size_t keylen)
{
	struct rte_ipsec_sa_prm prm;
	struct rte_crypto_sym_xform aead;
	size_t sa_sz;
	uint32_t salt, src, dst;

	(void)keylen;
	if (rsa->mode != R2DP_MODE_TUNNEL)
		return -EOPNOTSUPP;
	if (rsa->enc != R2DP_ENCR_AES_GCM_16)
		return -EOPNOTSUPP;
	if (rsa->enckeylen != 20)
		return -EINVAL;
	if (addr4_to_u32(&rsa->src, &src) < 0 ||
	    addr4_to_u32(&rsa->dst, &dst) < 0)
		return -EAFNOSUPPORT;

	sa_sz = rte_ipsec_sa_size(NULL);
	if (sa_sz == 0)
		return -EINVAL;
	ds->sa = rte_zmalloc(NULL, sa_sz, RTE_CACHE_LINE_SIZE);
	if (!ds->sa)
		return -ENOMEM;

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
	prm.crypto_xform = &aead;

	prm.ipsec_xform.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
	prm.ipsec_xform.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL;
	prm.ipsec_xform.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
	prm.ipsec_xform.spi = ntohl(rsa->spi);
	prm.ipsec_xform.salt = salt;
	prm.ipsec_xform.options.esn = (rsa->saflags & R2DP_SAF_ESN) ? 1 : 0;
	prm.ipsec_xform.replay_win_sz = rsa->wsize;
	prm.ipsec_xform.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;

	/* outer IPv4 tunnel header template (by value; no pointers into rsa) */
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

	if (rte_ipsec_sa_init(ds->sa, &prm, 0) < 0) {
		rte_free(ds->sa);
		ds->sa = NULL;
		return -EINVAL;
	}
	ds->spi = ntohl(rsa->spi);
	ds->proto = rsa->proto;
	ds->used = 1;
	return 0;
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
				if (d->sa_tab[i].sa)
					rte_ipsec_sa_fini(d->sa_tab[i].sa);
				rte_free(d->sa_tab[i].sa);
				memset(&d->sa_tab[i], 0, sizeof(d->sa_tab[i]));
				break;
			}
		}
		rte_spinlock_unlock(&d->lock);
		return 0;
	}

	for (int i = 0; i < MAX_SA; i++)
		if (!d->sa_tab[i].used) { idx = i; break; }
	if (idx < 0) {
		rte_spinlock_unlock(&d->lock);
		return -ENOSPC;
	}

	ret = dp_sa_init(&d->sa_tab[idx], rsa, key, keylen);
	if (ret < 0) {
		rte_spinlock_unlock(&d->lock);
		return ret;
	}

	memset(&keyv, 0, sizeof(keyv));
	keyv.v4.spi = ntohl(rsa->spi);
	keyv.v4.dip = dip;
	ret = rte_ipsec_sad_add(d->sad, &keyv, RTE_IPSEC_SAD_SPI_DIP,
	    d->sa_tab[idx].sa);
	if (ret < 0) {
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
static struct fwd_dp_ops dpdk_ops = {
	.caps   = dpdk_caps,
	.sa_add = dpd_sa_add,
	.sp_add = dpd_sp_add,
	.sp_del = dpd_sp_del,
};

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
	RTE_ETH_FOREACH_DEV(port) {
		struct rte_eth_dev_info di;
		if (rte_eth_dev_info_get(port, &di) == 0 &&
		    strstr(di.driver_name, "tap")) {
			d->port_id = port;
			break;
		}
	}

	dp->priv = d;
	dp->ops = &dpdk_ops;
	if (dp->ops->caps)
		dp->ops->caps(dp->ops->caps_bits_enc, dp->ops->caps_bits_integ);
	fprintf(stderr, "r2dp-fwd: DPDK dataplane ready (port=%d cdev=%d sad=%p)\n",
	    d->port_id, d->cdev_id, (void *)d->sad);
	return 0;
}

#endif /* R2DP_HAVE_DPDK */

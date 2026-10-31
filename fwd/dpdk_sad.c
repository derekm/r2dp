/*
 * fwd/dpdk_sad.c -- DPDK data plane: SA table.
 * 
 * r2dp SA -> rte_ipsec_sa + crypto session, the inbound SAD (SPI, DIP),
 * slot install/retire under d->lock with QSBR grace periods, byte-lifetime
 * counters, and the capability bits the transforms above actually support.
 */
#ifdef R2DP_HAVE_DPDK

#include "dpdk_int.h"

/* ------------------------------------------------------------------ */
void
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
	ds->rp_w = r2dp_sa_window(rsa); /* 0 = off; ctl caps it at RP_BITS */
	ds->rp_esn = (rsa->saflags & R2DP_SAF_ESN) != 0;
	/* tunnel endpoints: addr4_to_u32 memcpy's rsa->dst.addr[0..4], raw wire
	 * order; match that exactly for endpoint selection (H3). */
	memcpy(&ds->dsta, &rsa->dst.addr[0], 4);
	memcpy(&ds->srca, &rsa->src.addr[0], 4);
	ds->used = 1;
	return 0;
}

/* Tear down one slot: free the crypto session, ipsec SA, and zero it.
 * Caller holds d->lock. */
void
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
int
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
	/* iked's NAT-T ports (the peer's may be NAT-mapped); 0 -> 4500 */
	d->sa_tab[newidx].natt_sport = rsa->natt_sport ? rsa->natt_sport :
	    rte_cpu_to_be_16(NATT_PORT);
	d->sa_tab[newidx].natt_dport = rsa->natt_dport ? rsa->natt_dport :
	    rte_cpu_to_be_16(NATT_PORT);
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
int
dpd_sa_add(struct fwd_dp *dp, int add, const struct r2dp_sa *sa,
    const void *blob, size_t blen)
{
	struct dpdk_priv *d = dp->priv;

	return sa_install(d, sa, blob, blen, !(add & 1),
	    (add & FWD_DP_SA_INBOUND) != 0);
}

/* dataplane vtable (process-static so it outlives the probe).  Not const:
 * the .caps callback fills dp->ops->caps_bits_* in place. */
int64_t
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

/* Recover the dp_sa owning an ipsec session handed back by the SAD. */
struct dp_sa *
sa_of_sess(struct dpdk_priv *d, struct rte_ipsec_session *ss)
{
	struct dp_sa *ds = (struct dp_sa *)((uint8_t *)ss -
	    offsetof(struct dp_sa, sess));
	uintptr_t base = (uintptr_t)d->sa_tab, end = base + sizeof(d->sa_tab);

	return ((uintptr_t)ds >= base && (uintptr_t)ds < end) ? ds : NULL;
}


#endif /* R2DP_HAVE_DPDK */

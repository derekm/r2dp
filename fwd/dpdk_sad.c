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

/* ---- growth (ctl thread, d->lock held) --------------------------- */

static uint32_t pool_gen;     /* process-wide: DPDK object names are global */

static int
grow_fail_injected(struct dpdk_priv *d)
{
	if (!d->inject_grow_fail)
		return 0;
	d->inject_grow_fail--;
	return 1;
}

static void *
chunk_alloc(struct dpdk_priv *d, size_t esz)
{
	size_t sz = (size_t)DP_CHUNK * esz;
	void *p;

	if (grow_fail_injected(d))
		return NULL;
	p = aligned_alloc(RTE_CACHE_LINE_SIZE,
	    RTE_ALIGN_CEIL(sz, RTE_CACHE_LINE_SIZE));
	if (p)
		memset(p, 0, sz);
	return p;
}

/* Add one chunk of SA slots and publish it: the chunk pointer first, then
 * the new cap with a release store.  Existing slots never move. */
int
dp_sa_grow(struct dpdk_priv *d)
{
	uint32_t c = d->sa_cap / DP_CHUNK;
	struct dp_sa *ch;

	if (c >= DP_MAX_CHUNKS || !(ch = chunk_alloc(d, sizeof(*ch)))) {
		d->n_grow_fail++;
		return -ENOMEM;
	}
	for (uint32_t i = 0; i < DP_CHUNK; i++)
		ch[i].idx = c * DP_CHUNK + i;
	__atomic_store_n(&d->sa_chunk[c], ch, __ATOMIC_RELEASE);
	__atomic_store_n(&d->sa_cap, (c + 1) * DP_CHUNK, __ATOMIC_RELEASE);
	d->n_grow++;
	return 0;
}

int
dp_sp_grow(struct dpdk_priv *d)
{
	uint32_t c = d->sp_cap / DP_CHUNK;
	struct dp_sp_ent *ch;

	if (c >= DP_MAX_CHUNKS || !(ch = chunk_alloc(d, sizeof(*ch)))) {
		d->n_grow_fail++;
		return -ENOMEM;
	}
	__atomic_store_n(&d->sp_chunk[c], ch, __ATOMIC_RELEASE);
	__atomic_store_n(&d->sp_cap, (c + 1) * DP_CHUNK, __ATOMIC_RELEASE);
	d->n_grow++;
	return 0;
}

/* Grow ahead of need (at 75% use) so that a failed allocation costs
 * nothing while free slots remain; grow on demand when none are left.
 * Returns a free SA slot, or -ENOMEM only when the table is full and
 * cannot grow (existing SAs are untouched either way). */
static int
sa_free_slot(struct dpdk_priv *d)
{
	if ((uint64_t)(d->sa_n + 1) * 4 > (uint64_t)d->sa_cap * 3)
		(void)dp_sa_grow(d);
	for (uint32_t i = 0; i < d->sa_cap; i++)
		if (!sa_at(d, i)->used)
			return (int)i;
	if (dp_sa_grow(d) < 0)
		return -ENOMEM;
	return (int)(d->sa_cap - DP_CHUNK);
}

/* Free all chunks (teardown; no worker running). */
void
dp_tables_free(struct dpdk_priv *d)
{
	for (uint32_t c = 0; c < DP_MAX_CHUNKS; c++) {
		free(d->sa_chunk[c]);
		free(d->sp_chunk[c]);
		d->sa_chunk[c] = NULL;
		d->sp_chunk[c] = NULL;
	}
	d->sa_cap = d->sp_cap = d->sa_n = d->sp_n = 0;
	/* overflow session pools (every session must be freed by now) */
	for (uint32_t i = 0; i < d->n_sess_more; i++)
		rte_mempool_free(d->sess_more[i]);
	d->n_sess_more = 0;
}

static struct rte_cryptodev_sym_session *
sess_create(struct dpdk_priv *d, struct rte_crypto_sym_xform *x)
{
	struct rte_cryptodev_sym_session *s;
	struct rte_mempool *mp;
	char name[RTE_MEMPOOL_NAMESIZE];

	s = rte_cryptodev_sym_session_create(d->cdev_id, x, d->sess_mp);
	for (uint32_t i = 0; !s && i < d->n_sess_more; i++)
		s = rte_cryptodev_sym_session_create(d->cdev_id, x,
		    d->sess_more[i]);
	if (s || !d->sess_mp)
		return s;
	if (d->n_sess_more >= DP_MAX_SESS_POOLS || grow_fail_injected(d)) {
		d->n_grow_fail++;
		return NULL;
	}
	snprintf(name, sizeof(name), "r2dp_sess%u",
	    __atomic_add_fetch(&pool_gen, 1, __ATOMIC_RELAXED));
	mp = rte_cryptodev_sym_session_pool_create(name, DP_SESS_POOL,
	    rte_cryptodev_sym_get_private_session_size(d->cdev_id), 0, 0,
	    SOCKET_ID_ANY);
	if (!mp) {
		d->n_grow_fail++;
		return NULL;
	}
	d->sess_more[d->n_sess_more++] = mp;
	d->n_grow++;
	return rte_cryptodev_sym_session_create(d->cdev_id, x, mp);
}

/* Inbound SAD growth: build a SAD of twice the capacity holding every
 * live inbound SA, publish it, and destroy the old one after a grace
 * period (workers keep looking up in the old one until then).  On failure
 * the old SAD keeps serving.  d->sad_cap == 0: fixed-size SAD (tests). */
static int
sad_grow(struct dpdk_priv *d)
{
	struct rte_ipsec_sad_conf conf;
	struct rte_ipsec_sad *ns, *old = d->sad;
	char name[RTE_IPSEC_SAD_NAMESIZE];
	uint32_t ncap = d->sad_cap * 2;

	if (grow_fail_injected(d)) {
		d->n_grow_fail++;
		return -ENOMEM;
	}
	memset(&conf, 0, sizeof(conf));
	conf.socket_id = SOCKET_ID_ANY;
	conf.max_sa[RTE_IPSEC_SAD_SPI_DIP] = ncap;
	conf.flags = RTE_IPSEC_SAD_FLAG_RW_CONCURRENCY;
	snprintf(name, sizeof(name), "r2dp_sad%u",
	    __atomic_add_fetch(&pool_gen, 1, __ATOMIC_RELAXED));
	ns = rte_ipsec_sad_create(name, &conf);
	if (!ns) {
		d->n_grow_fail++;
		return -ENOMEM;
	}
	for (uint32_t i = 0; i < d->sa_cap; i++) {
		struct dp_sa *ds = sa_at(d, i);
		union rte_ipsec_sad_key k;

		if (!ds->used || !ds->inbound)
			continue;
		memset(&k, 0, sizeof(k));
		k.v4.spi = ds->spi;
		k.v4.dip = ds->dip;
		if (rte_ipsec_sad_add(ns, &k, RTE_IPSEC_SAD_SPI_DIP,
		    &ds->sess) < 0) {
			rte_ipsec_sad_destroy(ns);
			d->n_grow_fail++;
			return -ENOMEM;
		}
	}
	__atomic_store_n(&d->sad, ns, __ATOMIC_RELEASE);
	d->sad_cap = ncap;
	d->n_grow++;
	if (d->rcu)
		r2dp_qsbr_sync(d->rcu);
	rte_ipsec_sad_destroy(old);
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
	/* only ESP: an AH (or IPComp) SA would otherwise be installed as
	 * ESP-GCM -- different protection than asked for (the upstream
	 * prototype refuses it the same way) */
	if (rsa->proto != R2DP_PROTO_ESP)
		return -EOPNOTSUPP;
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

	/* crypto session: from the first pool with room, adding a pool when
	 * they are all full (sessions go back to their own pool on free) */
	ds->cses = sess_create(d, &aead);
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
	{
		uint32_t idx = ds->idx;
		memset(ds, 0, sizeof(*ds));
		ds->idx = idx;
	}
}

/* H5: retire a slot the worker may currently be using.  Step 1 (unlink):
 * clear `used` under the lock so SA/SP lookups stop returning this session,
 * and drop it from the inbound SAD.  Step 2: wait for the worker to pass a
 * grace period (it reports quiescent after each loop, i.e. after its crypto
 * path has finished touching every session it grabbed this iteration).  Only
 * then free the session memory -- this is what prevents the ctl<->worker
 * use-after-free on SA_DEL / rekey under traffic.  Caller holds d->lock. */
static void
sa_slot_retire(struct dpdk_priv *d, struct dp_sa *ds, int sad_del)
{
	union rte_ipsec_sad_key keyv;
	int inbound = ds->inbound && sad_del;

	__atomic_store_n(&ds->used, 0, __ATOMIC_RELEASE); /* unlink from worker */
	if (inbound) {
		memset(&keyv, 0, sizeof(keyv));
		keyv.v4.spi = ds->spi;
		keyv.v4.dip = ds->dip;
		if (rte_ipsec_sad_del(d->sad, &keyv, RTE_IPSEC_SAD_SPI_DIP) == 0 &&
		    d->sad_n)
			d->sad_n--;
	}
	if (d->rcu)
		r2dp_qsbr_sync(d->rcu);
	sa_slot_free(d, ds);
}

/* ------------------------------------------------------------------ */
int
sa_install(struct dpdk_priv *d, const struct r2dp_sa *rsa,
    const void *key, size_t keylen, int remove, int inbound)
{
	union rte_ipsec_sad_key keyv;
	uint32_t dip = 0, sip = 0;
	int idx = -1, ret;

	if (addr4_to_u32(&rsa->dst, &dip) < 0)
		return -EAFNOSUPPORT;
	(void)addr4_to_u32(&rsa->src, &sip);

	rte_spinlock_lock(&d->lock);

	if (remove) {
		for (uint32_t i = 0; i < d->sa_cap; i++) {
			struct dp_sa *x = sa_at(d, i);
			if (x->used && x->spi == ntohl(rsa->spi) &&
			    x->proto == rsa->proto && x->dip == dip) {
				sa_slot_retire(d, x, 1);
				d->sa_n--;
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
	for (uint32_t i = 0; i < d->sa_cap; i++) {
		struct dp_sa *x = sa_at(d, i);
		if (x->used && x->proto == rsa->proto &&
		    x->spi == ntohl(rsa->spi) && x->dip == dip) {
			idx = (int)i;
			break;
		}
	}

	/* M2 (build-then-swap): build the NEW session first so a failure leaves
	 * the old SA untouched (ctl still holds the old one as last-known-good).
	 * Only after the new session exists do we tear the old one down and
	 * publish the new one -- no window where the dataplane has nothing. */
	int newidx = sa_free_slot(d);
	struct dp_sa *nd;
	if (newidx < 0) {
		rte_spinlock_unlock(&d->lock);
		return newidx;
	}
	nd = sa_at(d, (uint32_t)newidx);
	/* inbound: make room in the SAD before anything is published, so a
	 * failure leaves every existing SA as it was */
	if (inbound && d->sad_cap &&
	    (uint64_t)(d->sad_n + 1) * 4 > (uint64_t)d->sad_cap * 3 &&
	    sad_grow(d) < 0 && d->sad_n + 1 > d->sad_cap) {
		rte_spinlock_unlock(&d->lock);
		return -ENOMEM;
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
		scratch.idx = (uint32_t)newidx;
		*nd = scratch;
	}
	nd->spi = ntohl(rsa->spi);
	nd->proto = rsa->proto;
	nd->reqid = rsa->reqid;
	nd->dip = dip;
	nd->inbound = inbound;
	nd->natt = rsa->natt_type;
	nd->owner = dp_owner(d->nb_wk, sip, dip);
	/* iked's NAT-T ports (the peer's may be NAT-mapped); 0 -> 4500 */
	nd->natt_sport = rsa->natt_sport ? rsa->natt_sport :
	    rte_cpu_to_be_16(NATT_PORT);
	nd->natt_dport = rsa->natt_dport ? rsa->natt_dport :
	    rte_cpu_to_be_16(NATT_PORT);
	nd->hard_bytes = rsa->lft_hard_bytes;
	nd->gen = ++d->sa_gen;
	/* publish last: the worker only proceeds past `used` == 1 */
	__atomic_store_n(&nd->used, 1, __ATOMIC_RELEASE);
	d->sa_n++;

	/* Rebind policies before retiring the old session: a rekey switches
	 * egress to the newest SA with no window where the policy has none.
	 * A failed rebuild leaves the previous snapshot, whose bindings the
	 * worker re-validates by generation (stale => drop, never misuse). */
	(void)spd_rebuild(d);

	/* Inbound: point the (SPI, DIP) SAD key at the new session before the
	 * old one goes.  rte_ipsec_sad_add on an existing key replaces its
	 * value, so during a same-SPI update every lookup returns the old or
	 * the new session, never a miss.  On failure the new SA is retired
	 * and the old one keeps serving. */
	if (inbound) {
		memset(&keyv, 0, sizeof(keyv));
		keyv.v4.spi = ntohl(rsa->spi);
		keyv.v4.dip = dip;
		if (d->verbose)
			fprintf(stderr, "r2dp-fwd: SA_ADD key spi=%08x dip=%08x "
			    "(rsa.spi=%08x raw dip=%08x)\n", ntohl(rsa->spi),
			    dip, rsa->spi, dip);
		ret = rte_ipsec_sad_add(d->sad, &keyv, RTE_IPSEC_SAD_SPI_DIP,
		    &nd->sess);   /* SAD value = the ipsec session ptr */
		if (ret < 0) {
			/* published already: unlink, wait out readers, free */
			sa_slot_retire(d, nd, 0);
			d->sa_n--;
			(void)spd_rebuild(d);
			rte_spinlock_unlock(&d->lock);
			return ret;
		}
		if (idx < 0)
			d->sad_n++;
	}
	/* tear down the old same-SPI session (now that a replacement exists);
	 * its SAD key already maps to the new session */
	if (idx >= 0) {
		sa_slot_retire(d, sa_at(d, (uint32_t)idx), 0);
		d->sa_n--;
	}
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
	for (uint32_t i = 0; i < d->sa_cap; i++) {
		struct dp_sa *x = sa_at(d, i);
		if (x->used && x->spi == spi && x->dip == dip) {
			v = (int64_t)__atomic_load_n(&x->bytes,
			    __ATOMIC_RELAXED);
			break;
		}
	}
	rte_spinlock_unlock(&d->lock);
	return v;
}

int
dpd_sa_set_hard_bytes(struct fwd_dp *dp, uint32_t spi, uint32_t dip,
    uint64_t hard)
{
	struct dpdk_priv *d = dp->priv;
	int rc = -ENOENT;
	rte_spinlock_lock(&d->lock);
	for (uint32_t i = 0; i < d->sa_cap; i++) {
		struct dp_sa *x = sa_at(d, i);
		if (x->used && x->spi == spi && x->dip == dip) {
			__atomic_store_n(&x->hard_bytes, hard, __ATOMIC_RELAXED);
			rc = 0;
		}
	}
	rte_spinlock_unlock(&d->lock);
	return rc;
}

/* Recover the dp_sa owning an ipsec session handed back by the SAD. */
struct dp_sa *
sa_of_sess(struct dpdk_priv *d, struct rte_ipsec_session *ss)
{
	struct dp_sa *ds = (struct dp_sa *)((uint8_t *)ss -
	    offsetof(struct dp_sa, sess));

	return ds->idx < sa_cap(d) && sa_at(d, ds->idx) == ds ? ds : NULL;
}


#endif /* R2DP_HAVE_DPDK */

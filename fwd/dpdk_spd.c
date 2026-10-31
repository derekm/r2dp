/*
 * fwd/dpdk_spd.c -- DPDK data plane: security policy database.
 * 
 * Policy copies published to the workers, the immutable SPD snapshot
 * (rte_acl OUT classifier with policies bound to their egress SA at control
 * time, the per-SA inbound policy index, the tunnel-peer set), and the
 * packet-side lookups over it.
 */
#ifdef R2DP_HAVE_DPDK

#include "dpdk_int.h"

int
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

int
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

/* RFC 4301 s5.2 inbound check, tied to the SA the packet decrypted under.
 * The SA's IN (or FWD) PROTECT policies are those whose tunnel endpoints
 * are this SA's (tun_src = SA src = peer, tun_dst = SA dst = us) and, when
 * both carry a nonzero reqid, whose reqid matches.  The inner packet must
 * match one of them; a peer with a valid SA must not inject traffic for
 * another tunnel's selectors.  No policy for this SA => drop (default
 * deny).  Returns 1 to accept. */
int
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

/* Find the EGRESS SA for this OUT policy.  racoon2 sends reqid=0 for every
 * SP and SA, so reqid alone would collapse all tunnels onto the first
 * outbound SA (H3).  Prefer an exact tunnel-endpoint match (policy tun_src/
 * tun_dst == SA src/dst); among endpoint matches prefer a real (nonzero)
 * reqid when the policy carries one; within each class take the newest SA
 * (highest install gen) so a rekey overlap encrypts with the new SA. */
struct dp_sa *
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
int
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

int
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
void
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
const struct r2dp_sp *
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

/* sp_match_out for a burst: one rte_acl_classify over every packet that
 * parses (the trie walk is vectorised across the burst and the snapshot is
 * loaded once).  ip[i] == NULL or an unparsable header yields sp[i] = NULL,
 * sa[i] = NULL, exactly as sp_match_out would. */
void
sp_match_out_burst(struct dpdk_priv *d, const struct rte_ipv4_hdr *const ip[],
    const size_t avail[], uint16_t n, const struct r2dp_sp *sp[],
    struct dp_sa *sa[])
{
	const struct dp_spd *s = __atomic_load_n(&d->spd, __ATOMIC_ACQUIRE);
	struct acl_key k[BURST_SZ];
	const uint8_t *data[BURST_SZ];
	uint32_t res[BURST_SZ];
	uint16_t idx[BURST_SZ], nk = 0;

	for (uint16_t i = 0; i < n; i++) {
		sp[i] = NULL;
		sa[i] = NULL;
		if (s && s->acl && ip[i] &&
		    acl_key_fill(&k[nk], (const uint8_t *)ip[i], avail[i])) {
			data[nk] = (const uint8_t *)&k[nk];
			idx[nk++] = i;
		}
	}
	if (!nk || rte_acl_classify(s->acl, data, res, nk, 1) != 0)
		return;
	for (uint16_t j = 0; j < nk; j++)
		sp[idx[j]] = spd_resolve(d, s, res[j], &sa[idx[j]]);
}

/* Is `ip` (raw wire order) the far end of a configured tunnel?  Far end =
 * src of an inbound SA, dst of an outbound SA, or tun_dst/tun_src of a
 * PROTECT OUT/IN policy (policies exist before IKE completes, so the
 * initiator can learn from the peer's IKE replies). */
int
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

#endif /* R2DP_HAVE_DPDK */

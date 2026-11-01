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
	uint64_t oldver;
	int slot = -1;

	if (!sp->slid)
		return -EINVAL;
	nsp = malloc(sizeof(*nsp));
	if (!nsp)
		return -ENOMEM;
	*nsp = *sp;                 /* fully built before it is published */
	rte_spinlock_lock(&d->lock);
	for (uint32_t i = 0; i < d->sp_cap; i++) {
		const struct r2dp_sp *x = sp_at(d, i)->sp;
		if (x) {
			if (x->slid == sp->slid) { slot = (int)i; break; }
		} else if (slot < 0)
			slot = (int)i;
	}
	/* grow ahead at 75% use; on demand when no slot is free */
	if ((slot < 0 || (uint64_t)(d->sp_n + 1) * 4 > (uint64_t)d->sp_cap * 3) &&
	    dp_sp_grow(d) == 0 && slot < 0)
		slot = (int)(d->sp_cap - DP_CHUNK);
	if (slot < 0) {
		rte_spinlock_unlock(&d->lock);
		free(nsp);
		return -ENOMEM;
	}
	old = sp_at(d, (uint32_t)slot)->sp;
	oldver = sp_at(d, (uint32_t)slot)->ver;
	sp_at(d, (uint32_t)slot)->ver = ++d->sp_ver;
	__atomic_store_n(&sp_at(d, (uint32_t)slot)->sp, nsp, __ATOMIC_RELEASE);
	if (spd_rebuild_ex(d, 1) < 0) {
		/* the worker keeps enforcing the previous snapshot; put the
		 * table back so control state and dataplane agree */
		sp_at(d, (uint32_t)slot)->ver = oldver;
		__atomic_store_n(&sp_at(d, (uint32_t)slot)->sp, old,
		    __ATOMIC_RELEASE);
		if (d->rcu)
			r2dp_qsbr_sync(d->rcu);
		rte_spinlock_unlock(&d->lock);
		free(nsp);
		return -ENOMEM;
	}
	if (!old)
		d->sp_n++;
	if (old) {
		/* spd_rebuild waited a grace period after publishing the
		 * snapshot that no longer references `old`; the direct SP-table
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
	for (uint32_t i = 0; i < d->sp_cap; i++) {
		struct dp_sp_ent *e = sp_at(d, i);
		if (e->sp && e->sp->slid == sp->slid) {
			old = e->sp;
			__atomic_store_n(&e->sp, NULL, __ATOMIC_RELEASE);
			if (spd_rebuild_ex(d, 1) < 0) {
				/* keep enforcing the old (stricter or equal)
				 * policy rather than dropping it unseen */
				__atomic_store_n(&e->sp, old, __ATOMIC_RELEASE);
				rte_spinlock_unlock(&d->lock);
				return -ENOMEM;
			}
			d->sp_n--;
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
	uint32_t j = ds->idx, n;

	/* fast path: the snapshot's per-SA list, if it was built for this
	 * very SA install (gen match) */
	if (s && s->in_off && j < s->in_cap && sa_at(d, j) == ds &&
	    s->in_gen[j] == ds->gen) {
		for (uint32_t k = s->in_off[j]; k < s->in_off[j + 1]; k++)
			if (r2dp_sel_match(s->in_pol[k], ip, avail))
				return 1;
		return 0;
	}
	/* snapshot not (yet) rebuilt for this SA: full scan */
	n = sp_cap(d);
	for (uint32_t i = 0; i < n; i++) {
		const struct r2dp_sp *sp = sp_load(sp_at(d, i));
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
	for (i = 0; i < (int)d->sa_cap; i++) {
		struct dp_sa *ds = sa_at(d, (uint32_t)i);
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
acl_put(struct dp_acl *a)
{
	if (!a || --a->refs)
		return;
	rte_acl_free(a->ctx);
	free(a->sorted);
	free(a);
}

static void
spd_free(struct dp_spd *s)
{
	if (!s)
		return;
	acl_put(s->acl);
	free(s->acl_map);
	free(s->delta);
	free(s->out);
	free(s->in_off);
	free(s->in_gen);
	free(s->in_pol);
	free(s->peer);
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

static int
ver_cmp(const void *a, const void *b)
{
	const uint64_t *x = a, *y = b;
	return x[0] < y[0] ? -1 : x[0] > y[0];
}

/* Compile a policy's selector for pol_match (and say whether rte_acl gets
 * a rule for it: non-IPv4 selectors or prefix > 32 can never match). */
static void
pol_compile(struct dp_pol *p)
{
	const struct r2dp_sp *sp = p->sp;

	p->v4 = sp->sel_src.family == R2DP_AF_INET4 &&
	    sp->sel_dst.family == R2DP_AF_INET4 &&
	    sp->pref_src <= 32 && sp->pref_dst <= 32;
	if (!p->v4)
		return;
	p->smask = sp->pref_src ? htonl(~0u << (32 - sp->pref_src)) : 0;
	p->dmask = sp->pref_dst ? htonl(~0u << (32 - sp->pref_dst)) : 0;
	memcpy(&p->src, sp->sel_src.addr, 4);
	memcpy(&p->dst, sp->sel_dst.addr, 4);
	p->src &= p->smask;
	p->dst &= p->dmask;
	p->sport = sp->sel_src.port;
	p->dport = sp->sel_dst.port;
	p->proto = sp->ul_proto == R2DP_PROTO_ANY ? 0 : sp->ul_proto;
}

/* Same predicate as the rte_acl rule (and r2dp_sel_match): k is filled by
 * acl_key_fill, ports 0 when not comparable, so a port selector (never 0)
 * cannot match then. */
static inline int
pol_match(const struct dp_pol *p, const struct acl_key *k)
{
	return p->v4 && ((k->src & p->smask) == p->src) &&
	    ((k->dst & p->dmask) == p->dst) &&
	    (!p->proto || k->proto == p->proto) &&
	    (!p->sport || k->sport == p->sport) &&
	    (!p->dport || k->dport == p->dport);
}

/* Build an rte_acl classifier over s->out[] (already sorted).  Policies a
 * full scan could never match (!v4) get no rule.  Priority = rank in out[]
 * (score, then table slot): the same winner as r2dp_sel_match +
 * r2dp_sel_score over the SP table.  The relative order of two policies
 * never changes while both live, so a reused classifier still ranks its
 * live rules right.  Built entirely to the side: on any failure the caller
 * publishes nothing. */
static int
spd_build_acl(struct dpdk_priv *d, struct dp_spd *s)
{
	static uint32_t gen;
	struct rte_acl_param prm;
	struct rte_acl_config cfg;
	struct dp_acl_rule *rules = NULL;
	struct dp_acl *a = NULL;
	char name[RTE_ACL_NAMESIZE];
	uint32_t n = 0;
	int ret = -ENOMEM;

	s->acl = NULL;
	s->ndead = s->ndelta = 0;
	if (!s->nout)
		return 0;
	rules = calloc(s->nout, sizeof(*rules));
	a = calloc(1, sizeof(*a));
	s->acl_map = malloc(s->nout * sizeof(*s->acl_map));
	if (!rules || !a || !s->acl_map)
		goto out;
	a->sorted = malloc(2 * s->nout * sizeof(*a->sorted));
	if (!a->sorted)
		goto out;
	for (uint32_t i = 0; i < s->nout; i++) {
		const struct r2dp_sp *sp = s->out[i].sp;
		struct dp_acl_rule *r = &rules[n];

		if (!s->out[i].v4)
			continue;
		r->data.category_mask = 1;
		/* out[] is sorted best first: rank is the priority */
		r->data.priority = (int32_t)(s->nout - i);
		r->data.userdata = n + 1;
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
		a->sorted[2 * n] = s->out[i].ver;
		a->sorted[2 * n + 1] = n;
		s->acl_map[n] = (int32_t)i;
		n++;
	}
	if (!n) {
		ret = 0;
		goto out;
	}
	a->n = n;
	qsort(a->sorted, n, 2 * sizeof(*a->sorted), ver_cmp);
	snprintf(name, sizeof(name), "r2dp_spd_%u", __atomic_add_fetch(&gen, 1, __ATOMIC_RELAXED));
	memset(&prm, 0, sizeof(prm));
	prm.name = name;
	prm.socket_id = SOCKET_ID_ANY;
	prm.rule_size = RTE_ACL_RULE_SZ(AF_NUM);
	prm.max_rule_num = n;
	a->ctx = rte_acl_create(&prm);
	if (!a->ctx)
		goto out;
	if (rte_acl_add_rules(a->ctx, (const struct rte_acl_rule *)rules, n) != 0)
		goto out;
	memset(&cfg, 0, sizeof(cfg));
	cfg.num_categories = 1;
	cfg.num_fields = AF_NUM;
	memcpy(cfg.defs, acl_defs, sizeof(acl_defs));
	if (rte_acl_build(a->ctx, &cfg) != 0)
		goto out;
	a->refs = 1;
	s->acl = a;
	a = NULL;
	d->n_acl_build++;
	ret = 0;
out:
	free(rules);
	if (a) {
		if (a->ctx)
			rte_acl_free(a->ctx);
		free(a->sorted);
		free(a);
	}
	if (!s->acl) {
		free(s->acl_map);
		s->acl_map = NULL;
	}
	return ret;
}

/* Keep old's classifier for ns: map its rules onto ns->out[] and list the
 * policies it lacks.  0 if reused; -1 if a rebuild is due (too much drift,
 * or nothing to reuse); -ENOMEM. */
static int
spd_reuse_acl(struct dpdk_priv *d, const struct dp_spd *old, struct dp_spd *ns)
{
	const struct dp_acl *a = old ? old->acl : NULL;
	uint32_t na = a ? a->n : 0, live = 0, nd = 0;

	ns->delta = malloc((DP_ACL_DELTA + 1) * sizeof(*ns->delta));
	if (na)
		ns->acl_map = malloc(na * sizeof(*ns->acl_map));
	if (!ns->delta || (na && !ns->acl_map))
		return -ENOMEM;
	for (uint32_t r = 0; r < na; r++)
		ns->acl_map[r] = -1;
	for (uint32_t i = 0; i < ns->nout; i++) {
		uint64_t key = ns->out[i].ver;
		const uint64_t *hit;

		if (!ns->out[i].v4)
			continue;
		hit = na ? bsearch(&key, a->sorted, na, 2 * sizeof(*a->sorted),
		    ver_cmp) : NULL;
		if (hit) {
			ns->acl_map[hit[1]] = (int32_t)i;
			live++;
		} else {
			if (nd == DP_ACL_DELTA)
				return -1;
			ns->delta[nd++] = i;
		}
	}
	if (nd + (na - live) > DP_ACL_DELTA)
		return -1;
	ns->ndelta = nd;
	ns->ndead = na - live;
	if (a) {
		ns->acl = (struct dp_acl *)a;
		ns->acl->refs++;
	}
	d->n_acl_reuse++;
	return 0;
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

/* Build a new snapshot from the SP/SA tables, publish it, wait a grace period,
 * free the old one.  Caller holds d->lock.  On allocation failure nothing is
 * published and the worker keeps the previous snapshot. */
static inline uint32_t
peer_hash(uint32_t ip)
{
	uint32_t h = ip * 2654435761u;
	return h ^ (h >> 16);
}

static void
peer_put(struct dp_spd *s, uint32_t ip)
{
	uint32_t h;

	if (ip == 0) { s->peer_zero = 1; return; }
	for (h = peer_hash(ip) & s->peer_mask; s->peer[h] && s->peer[h] != ip;
	    h = (h + 1) & s->peer_mask)
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

/* Sorted (tunnel src, tunnel dst) index entries: the joins between SAs and
 * policies below binary-search them, so a rebuild costs O((SAs + SPs) log)
 * instead of SAs x SPs. */
struct ep_ent {
	uint32_t a, b;            /* endpoints, raw wire order */
	uint32_t slot;            /* SA or SP slot (tie-break: table order) */
};

static int
ep_cmp(const void *x, const void *y)
{
	const struct ep_ent *p = x, *q = y;

	if (p->a != q->a)
		return p->a < q->a ? -1 : 1;
	if (p->b != q->b)
		return p->b < q->b ? -1 : 1;
	return p->slot < q->slot ? -1 : p->slot > q->slot;
}

/* first entry with (a, b) >= key */
static uint32_t
ep_lower(const struct ep_ent *v, uint32_t n, uint32_t a, uint32_t b)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		uint32_t m = lo + (hi - lo) / 2;
		if (v[m].a < a || (v[m].a == a && v[m].b < b))
			lo = m + 1;
		else
			hi = m;
	}
	return lo;
}

/* Inbound per-SA policy index + peer hash (control time, d->lock held). */
static int
spd_build_in(struct dpdk_priv *d, struct dp_spd *s)
{
	uint32_t cap = d->sa_cap, scap = d->sp_cap, np = 0, k = 0, npeer = 0;
	struct ep_ent *pi = NULL;
	uint32_t hsz = PEER_HSZ_MIN;

	s->in_cap = cap;
	s->in_off = calloc((size_t)cap + 1, sizeof(*s->in_off));
	s->in_gen = calloc(cap ? cap : 1, sizeof(*s->in_gen));
	if (!s->in_off || !s->in_gen)
		return -ENOMEM;
	/* IN/FWD PROTECT policies by (tun_src, tun_dst) */
	pi = malloc(((size_t)scap + 1) * sizeof(*pi));
	if (!pi)
		return -ENOMEM;
	for (uint32_t i = 0; i < scap; i++) {
		const struct r2dp_sp *sp = sp_at(d, i)->sp;
		if (!sp || sp->action != R2DP_ACT_PROTECT)
			continue;
		npeer++;
		if (sp->dir != R2DP_DIR_IN && sp->dir != R2DP_DIR_FWD)
			continue;
		memcpy(&pi[np].a, &sp->tun_src.addr[0], 4);
		memcpy(&pi[np].b, &sp->tun_dst.addr[0], 4);
		pi[np++].slot = i;
	}
	qsort(pi, np, sizeof(*pi), ep_cmp);
	for (int pass = 0; pass < 2; pass++) {
		k = 0;
		for (uint32_t j = 0; j < cap; j++) {
			const struct dp_sa *ds = sa_at(d, j);
			if (pass)
				s->in_off[j] = k;
			if (!sa_live(ds) || !ds->inbound)
				continue;
			if (pass)
				s->in_gen[j] = ds->gen;
			for (uint32_t x = ep_lower(pi, np, ds->srca, ds->dsta);
			    x < np && pi[x].a == ds->srca && pi[x].b == ds->dsta;
			    x++) {
				const struct r2dp_sp *sp = sp_at(d, pi[x].slot)->sp;
				if (!in_pol_fits(sp, ds))
					continue;
				if (pass)
					s->in_pol[k] = sp;
				k++;
			}
		}
		if (!pass) {
			s->in_pol = calloc(k ? k : 1, sizeof(*s->in_pol));
			if (!s->in_pol) {
				free(pi);
				return -ENOMEM;
			}
		}
	}
	free(pi);
	s->in_off[cap] = k;
	npeer += d->sa_n;
	while (hsz < 4 * npeer && hsz < (1u << 30))
		hsz <<= 1;
	s->peer = calloc(hsz, sizeof(*s->peer));
	if (!s->peer)
		return -ENOMEM;
	s->peer_mask = hsz - 1;
	for (uint32_t j = 0; j < cap; j++) {
		const struct dp_sa *ds = sa_at(d, j);
		if (sa_live(ds))
			peer_put(s, ds->inbound ? ds->srca : ds->dsta);
	}
	for (uint32_t i = 0; i < scap; i++) {
		const struct r2dp_sp *sp = sp_at(d, i)->sp;
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

/* sa_by_policy over a sorted index of the live outbound SAs: same choice
 * (endpoint match; a nonzero matching reqid preferred; newest gen). */
static struct dp_sa *
sa_by_policy_ix(struct dpdk_priv *d, const struct ep_ent *v, uint32_t n,
    const struct r2dp_sp *sp)
{
	struct dp_sa *by_reqid = NULL, *by_endpoint = NULL;
	uint32_t ts, td;

	memcpy(&ts, &sp->tun_src.addr[0], 4);
	memcpy(&td, &sp->tun_dst.addr[0], 4);
	for (uint32_t x = ep_lower(v, n, ts, td);
	    x < n && v[x].a == ts && v[x].b == td; x++) {
		struct dp_sa *ds = sa_at(d, v[x].slot);
		if (sp->reqid && ds->reqid == sp->reqid) {
			if (!by_reqid || ds->gen > by_reqid->gen)
				by_reqid = ds;
		} else if (!by_endpoint || ds->gen > by_endpoint->gen)
			by_endpoint = ds;
	}
	return by_reqid ? by_reqid : by_endpoint;
}

static int
peer_has(const struct dp_spd *s, uint32_t ip)
{
	if (ip == 0)
		return s->peer_zero;
	for (uint32_t h = peer_hash(ip) & s->peer_mask; s->peer[h];
	    h = (h + 1) & s->peer_mask)
		if (s->peer[h] == ip)
			return 1;
	return 0;
}

/* Next hops follow tunnel peers: a peer that the previous snapshot had
 * (some live SA or PROTECT policy referenced it) and the new one lacks has
 * lost its last reference, so its learned MAC goes.  The peer set is
 * recomputed from the tables on every rebuild, which is the reference
 * count without one to drift; a peer still used by any SA or policy is
 * never touched.  The table recycles the slot after a QSBR grace period;
 * a worker that still resolves the peer finds the old MAC or none. */
static void
spd_peers_gone(struct dpdk_priv *d, const struct dp_spd *old,
    const struct dp_spd *ns)
{
	if (!d->nh.h)
		return;
	for (uint32_t h = 0; h <= old->peer_mask; h++) {
		uint32_t ip = old->peer[h];
		if (ip && !peer_has(ns, ip) && r2dp_nh_del(&d->nh, ip) > 0)
			d->n_nh_unref++;
	}
}

int
spd_rebuild_ex(struct dpdk_priv *d, int policies_changed)
{
	struct dp_spd *ns, *old;
	struct ep_ent *ov = NULL;
	uint32_t n = 0, nov = 0, cap = d->sa_cap, scap = d->sp_cap;

	ns = calloc(1, sizeof(*ns));
	if (!ns)
		goto fail;
	ns->out = calloc(scap ? scap : 1, sizeof(*ns->out));
	ov = malloc(((size_t)cap + 1) * sizeof(*ov));
	if (!ns->out || !ov)
		goto fail;
	for (uint32_t j = 0; j < cap; j++) {
		const struct dp_sa *ds = sa_at(d, j);
		if (!sa_live(ds) || ds->inbound)
			continue;
		ov[nov].a = ds->srca;
		ov[nov].b = ds->dsta;
		ov[nov++].slot = j;
	}
	qsort(ov, nov, sizeof(*ov), ep_cmp);
	for (uint32_t i = 0; i < scap; i++) {
		const struct r2dp_sp *sp = sp_at(d, i)->sp;
		struct dp_pol *p;
		struct dp_sa *ds;

		if (!sp || sp->dir != R2DP_DIR_OUT)
			continue;
		p = &ns->out[n++];
		p->sp = sp;
		p->slot = (int)i;
		p->score = r2dp_sel_score(sp);
		p->sa_idx = -1;
		p->ver = sp_at(d, i)->ver;
		pol_compile(p);
		if (sp->action != R2DP_ACT_BYPASS &&
		    (sp->sel_src.family == R2DP_AF_INET6 ||
		    sp->sel_dst.family == R2DP_AF_INET6))
			ns->v6_out = 1;
		if (sp->action == R2DP_ACT_PROTECT &&
		    (ds = sa_by_policy_ix(d, ov, nov, sp)) != NULL) {
			p->sa_idx = (int32_t)ds->idx;
			p->sa_gen = ds->gen;
		}
	}
	free(ov);
	ov = NULL;
	ns->nout = n;
	qsort(ns->out, n, sizeof(*ns->out), pol_cmp);
	if (spd_build_in(d, ns) < 0)
		goto fail;

	old = d->spd;
	/* Keep the classifier unless the policy set drifted too far from it
	 * (or a compaction is asked for): rebuilding rte_acl per policy add
	 * made installing n tunnels O(n^2). */
	{
		int r = policies_changed == 2 ? -1 : spd_reuse_acl(d, old, ns);
		if (r == -ENOMEM)
			goto fail;
		if (r < 0) {
			free(ns->acl_map);
			free(ns->delta);
			ns->acl_map = NULL;
			ns->delta = NULL;
			if (spd_build_acl(d, ns) < 0)
				goto fail;
		}
	}
	if (policies_changed)
		d->spd_dirty_tsc = (ns->ndelta || ns->ndead) ? rte_get_tsc_cycles() : 0;
	__atomic_store_n(&d->spd, ns, __ATOMIC_RELEASE);
	if (old) {
		if (d->rcu)
			r2dp_qsbr_sync(d->rcu);
		spd_peers_gone(d, old, ns);
		/* the next-hop maintenance thread reads the published snapshot
		 * (is_tunnel_peer via nh.wanted) under nh.lock and is no QSBR
		 * reader: wait until it is out before freeing */
		if (d->nh.wanted) {
			rte_spinlock_lock(&d->nh.lock);
			rte_spinlock_unlock(&d->nh.lock);
		}
		spd_free(old);       /* drops its classifier reference */
	}
	return 0;
fail:
	free(ov);
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
	for (uint32_t i = 0; i < d->sp_cap; i++) {
		free(sp_at(d, i)->sp);
		sp_at(d, i)->sp = NULL;
	}
	d->sp_n = 0;
	d->spd_dirty_tsc = 0;
}

void
spd_idle(struct dpdk_priv *d)
{
	uint64_t t = __atomic_load_n(&d->spd_dirty_tsc, __ATOMIC_RELAXED);

	if (!t || rte_get_tsc_cycles() - t <
	    rte_get_tsc_hz() / 1000 * DP_ACL_IDLE_MS)
		return;
	rte_spinlock_lock(&d->lock);
	if (d->spd_dirty_tsc && spd_rebuild_ex(d, 2) == 0)
		d->spd_dirty_tsc = 0;
	rte_spinlock_unlock(&d->lock);
}

/* Final OUT decision for one key: the classifier's best live rule, or a
 * better-ranked delta policy (out[] is sorted best first, so the lower
 * index wins); a hit on a dead rule falls back to a scan of out[].
 * Returns out[] index + 1, 0 = no policy. */
static inline uint32_t
spd_decide(const struct dp_spd *s, const struct acl_key *k, uint32_t res)
{
	uint32_t best = UINT32_MAX;

	if (res) {
		int32_t m = s->acl_map[res - 1];
		if (m < 0) {
			for (uint32_t i = 0; i < s->nout; i++)
				if (pol_match(&s->out[i], k))
					return i + 1;
			return 0;
		}
		best = (uint32_t)m;
	}
	for (uint32_t j = 0; j < s->ndelta; j++) {
		uint32_t i = s->delta[j];
		if (i < best && pol_match(&s->out[i], k))
			best = i;
	}
	return best == UINT32_MAX ? 0 : best + 1;
}

/* Resolve a decided OUT policy (out[] index+1, 0 = none) to the policy and
 * its control-time bound EGRESS SA (*sa NULL if none, or if the binding
 * went stale: retired/reused slot => generation mismatch => fail closed). */
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
		struct dp_sa *ds = sa_at(d, (uint32_t)p->sa_idx);
		if (sa_live(ds) && ds->gen == p->sa_gen && !ds->inbound)
			*sa = ds;
	}
	return p->sp;
}

/* Most specific OUT policy for one inner IPv4 packet (rte_acl over the
 * published snapshot, plus its delta list); DISCARD/BYPASS can override
 * PROTECT (M6), port selectors are honoured (M5).  The burst path
 * classifies all at once. */
const struct r2dp_sp *
sp_match_out(struct dpdk_priv *d, const struct rte_ipv4_hdr *ip, size_t avail,
    struct dp_sa **sa)
{
	const struct dp_spd *s = __atomic_load_n(&d->spd, __ATOMIC_ACQUIRE);
	struct acl_key k;
	const uint8_t *data[1] = { (const uint8_t *)&k };
	uint32_t res = 0;

	*sa = NULL;
	if (!s || !s->nout || !acl_key_fill(&k, (const uint8_t *)ip, avail))
		return NULL;
	if (s->acl && rte_acl_classify(s->acl->ctx, data, &res, 1, 1) != 0)
		return NULL;
	return spd_resolve(d, s, spd_decide(s, &k, res), sa);
}

/* sp_match_out for a burst: one rte_acl_classify over the burst's
 * distinct keys (the trie walk is vectorised across them and the snapshot
 * is loaded once); a packet whose key equals the previous distinct one --
 * the common case, a burst is mostly one flow -- reuses its result
 * (acl_key_fill zeroes the key, so the compare covers the padding too).
 * ip[i] == NULL or an unparsable header yields sp[i] = NULL, sa[i] = NULL,
 * exactly as sp_match_out would. */
void
sp_match_out_burst(struct dpdk_priv *d, const struct rte_ipv4_hdr *const ip[],
    const size_t avail[], uint16_t n, const struct r2dp_sp *sp[],
    struct dp_sa *sa[])
{
	const struct dp_spd *s = __atomic_load_n(&d->spd, __ATOMIC_ACQUIRE);
	struct acl_key k[BURST_SZ];
	const uint8_t *data[BURST_SZ];
	uint32_t res[BURST_SZ];
	int16_t ux[BURST_SZ];
	uint16_t nk = 0;

	if (n > BURST_SZ)
		n = BURST_SZ;
	for (uint16_t i = 0; i < n; i++) {
		ux[i] = -1;
		if (!s || !s->nout || !ip[i] ||
		    !acl_key_fill(&k[nk], (const uint8_t *)ip[i], avail[i]))
			continue;
		if (!nk || memcmp(&k[nk], &k[nk - 1], sizeof(k[0]))) {
			data[nk] = (const uint8_t *)&k[nk];
			nk++;
		}
		ux[i] = (int16_t)(nk - 1);
	}
	if (nk) {
		if (!s->acl)
			memset(res, 0, nk * sizeof(res[0]));
		else if (rte_acl_classify(s->acl->ctx, data, res, nk, 1) != 0)
			nk = 0;
		if (s->ndelta || s->ndead)
			for (uint16_t j = 0; j < nk; j++)
				res[j] = spd_decide(s, &k[j], res[j]);
		else
			for (uint16_t j = 0; j < nk; j++)
				res[j] = res[j] ? (uint32_t)s->acl_map[res[j] - 1] + 1 : 0;
	}
	for (uint16_t i = 0; i < n; i++) {
		sp[i] = NULL;
		sa[i] = NULL;
		if (nk && ux[i] >= 0)
			sp[i] = spd_resolve(d, s, res[ux[i]], &sa[i]);
	}
}

/* Is `ip` (raw wire order) the far end of a configured tunnel?  Far end =
 * src of an inbound SA, dst of an outbound SA, or tun_dst/tun_src of a
 * PROTECT OUT/IN policy (policies exist before IKE completes, so the
 * initiator can learn from the peer's IKE replies). */
int
is_tunnel_peer(struct dpdk_priv *d, uint32_t ip)
{
	const struct dp_spd *s = __atomic_load_n(&d->spd, __ATOMIC_ACQUIRE);

	return s ? peer_has(s, ip) : 0;
}

#endif /* R2DP_HAVE_DPDK */

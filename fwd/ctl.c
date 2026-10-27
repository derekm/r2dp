#define _GNU_SOURCE   /* SO_PEERCRED / struct ucred */
/*
 * fwd/ctl.c -- r2dp control-plane server for the DPDK forwarder.
 *
 * Listens on the r2dp unix SOCK_SEQPACKET socket and applies SAD/SPD
 * messages to the DPDK-backed dataplane.  This is the multi-backend seam:
 * mockfwd.c and fwd/ctl.c speak the same r2dp protocol; only the SAD/SPD
 * store differs (in-memory table vs rte_ipsec_sad / rte_acl).
 *
 * Protocol invariants (M0 findings) that must hold here too:
 *   - forwarder is the SAD source of truth (GETSPI allocates, SP_ADD is
 *     idempotent, SP_DUMP is called by spmd at startup and must be cheap)
 *   - AEAD key blob = cipher key || 4-byte salt (enclen=20 AES-128-GCM)
 *   - unknown transforms / mark / if_id refused (EOPNOTSUPP), not widened
 *
 * The dataplane interface is `struct fwd_dp` (fwd/dp.h): a thin set of
 * callbacks the DPDK dataplane implements.  ctl.c is hardware-agnostic.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/random.h>
#include <sys/socket.h>

#include "r2dp/client.h"
#include "dp.h"
#include "ctl.h"

#define MAXCLI 16


static struct fwd_ctl *C;
static volatile sig_atomic_t g_stop;

static void on_sig(int s) { (void)s; g_stop = 1; }

#define LOG(...) do { if (C && C->verbose) \
	{ fprintf(stderr, "r2dp: " __VA_ARGS__); fputc('\n', stderr); } } while (0)

/* first free SAD slot, or -1 */
static int
sa_alloc_idx(struct fwd_ctl *c)
{
	for (int i = 0; i < FWD_MAXSA; i++)
		if (!c->sad[i].used)
			return i;
	return -1;
}

/* ------------------------------------------------------------ SAD */
static struct fwd_sa_ent *
sa_find(struct fwd_ctl *c, const struct r2dp_sa *k)
{
	for (int i = 0; i < FWD_MAXSA; i++)
		if (c->sad[i].used && c->sad[i].sa.spi == k->spi &&
		    c->sad[i].sa.proto == k->proto &&
		    r2dp_addr_eq(&c->sad[i].sa.dst, &k->dst))
			return &c->sad[i];
	return NULL;
}

/* Data-plane hooks return -errno; the wire carries a positive errno
 * (libr2dp maps anything else to EPROTO, hiding the real reason). */
static int
dp_errno(int e)
{
	return e < 0 ? -e : e;
}

static int
sa_apply_dp(struct fwd_ctl *c, int add, const struct r2dp_sa *sa,
    const void *blob, size_t blen)
{
	if (c->dp.ops && c->dp.ops->sa_add)
		return c->dp.ops->sa_add(&c->dp, add, sa, blob, blen);
	return 0;
}

/* ------------------------------------------------------------ SPD */
static int
sel_eq_d(const struct r2dp_sp *a, const struct r2dp_sp *b)
{
	return a->dir == b->dir && a->ul_proto == b->ul_proto &&
	       a->pref_src == b->pref_src && a->pref_dst == b->pref_dst &&
	       r2dp_addr_eq(&a->sel_src, &b->sel_src) &&
	       a->sel_src.port == b->sel_src.port &&
	       r2dp_addr_eq(&a->sel_dst, &b->sel_dst) &&
	       a->sel_dst.port == b->sel_dst.port;
}

static struct fwd_sp_ent *
sp_find(struct fwd_ctl *c, const struct r2dp_sp *k, int by_selector)
{
	for (int i = 0; i < FWD_MAXSP; i++) {
		if (!c->spd[i].used)
			continue;
		if (by_selector ? sel_eq_d(&c->spd[i].sp, k) :
		    c->spd[i].sp.slid == k->slid)
			return &c->spd[i];
	}
	return NULL;
}

/* ----------------------------------------------------------- send */
/* Client sockets are non-blocking: a client that stops reading must never
 * stall the single control thread (and with it every other client and the
 * EXPIRE broadcast).  A send that would block, or fails, marks the client
 * slow/dead; fwd_ctl_run drops marked clients at the end of the pass. */
#define MAXBAD (MAXCLI * 2)
static int bad_fd[MAXBAD];
static int nbad;

static void
mark_bad(int fd)
{
	for (int i = 0; i < nbad; i++)
		if (bad_fd[i] == fd)
			return;
	if (nbad < MAXBAD)
		bad_fd[nbad++] = fd;
}

static int
is_bad(int fd)
{
	for (int i = 0; i < nbad; i++)
		if (bad_fd[i] == fd)
			return 1;
	return 0;
}

static int
csend(int fd, uint16_t type, uint32_t seq, int status, uint32_t flags,
    const void *body, size_t blen, const void *tail, size_t tlen)
{
	int r;

	if (is_bad(fd))
		return -EPIPE;     /* already being dropped: don't keep writing */
	r = r2dp_send(fd, type, seq, status, flags, body, blen, tail, tlen);
	if (r < 0) {
		LOG("dropping client fd=%d: send %s: %s", fd, r2dp_msg_name(type),
		    strerror(-r));
		mark_bad(fd);
	}
	return r;
}

/* ----------------------------------------------------------- reply */
static int
reply_sa(int fd, const struct r2dp_msg *req, int status,
    const struct fwd_sa_ent *e)
{
	const struct r2dp_sa *sa = e ? &e->sa : r2dp_msg_sa(req);
	return csend(fd, req->h.type, req->h.seq, status, R2DP_HF_NOKEYS,
	    sa, sizeof(*sa), NULL, 0);
}

static int
reply_sp(int fd, const struct r2dp_msg *req, int status,
    const struct r2dp_sp *sp, uint32_t flags)
{
	return csend(fd, req->h.type, req->h.seq, status, flags,
	    sp, sizeof(*sp), NULL, 0);
}

/* Reply to a DUMP request with one SA entry (flags may set R2DP_HF_MORE).
 * Always set NOKEYS: a dump completion must not carry key material, and
 * without it an SA carrying enckeylen>0 would fail the client's key-tail
 * validation (tail is absent). */
static int
reply_sa_dump(int fd, const struct r2dp_msg *req, int status,
    const struct r2dp_sa *sa, uint32_t flags)
{
	return r2dp_send(fd, R2DP_SA_DUMP, req->h.seq, status,
	    flags | R2DP_HF_NOKEYS, sa, sizeof(*sa), NULL, 0);
}

/* --------------------------------------------------------- handlers */
static void
do_hello(int fd, const struct r2dp_msg *m)
{
	struct r2dp_hello_ack a;
	const struct r2dp_hello *h = (const void *)m->body;

	memset(&a, 0, sizeof(a));
	a.epoch = C->epoch;
	a.max_msg = R2DP_MAX_MSG;
	/* Advertise only what the dataplane actually implements.  ESN, NAT-T and
	 * EXPIRE (soft/hard TIME-lifetime rekey driver, fwd/ctl.c) are wired;
	 * IPv6 is not, so it must not be advertised or racoon2 would negotiate
	 * it and fail. */
	a.features = R2DP_FEAT_ESN | R2DP_FEAT_NATT | R2DP_FEAT_EXPIRE;
	if (C->dp.ops && C->dp.ops->caps) {
		C->dp.ops->caps(&C->dp);
		memcpy(a.enc_caps, C->dp.caps_bits_enc, sizeof(a.enc_caps));
		memcpy(a.integ_caps, C->dp.caps_bits_integ, sizeof(a.integ_caps));
	} else {
		/* No dataplane registered: control-only mode.  Advertise NOTHING
		 * (0xff would falsely claim every algorithm is supported). */
		memset(a.enc_caps, 0, sizeof(a.enc_caps));
		memset(a.integ_caps, 0, sizeof(a.integ_caps));
	}
	LOG("HELLO role=%u pid=%u", h->role, h->pid);
	csend(fd, R2DP_HELLO_ACK, m->h.seq, 0, 0, &a, sizeof(a), NULL, 0);
}

static void
do_getspi(int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sa *rq = r2dp_msg_sa(m);
	uint32_t lo = rq->spi_min ? rq->spi_min : 0x100;
	uint32_t hi = rq->spi_max ? rq->spi_max : 0x0fffffff;
	struct fwd_sa_ent *e;
	uint32_t cand;
	int idx;

	/* SPIs 1..255 are reserved by IANA (RFC 4303 s2.1) and 0 is invalid:
	 * never hand one out, whatever range the client asks for. */
	if (rq->dst.family == R2DP_AF_UNSET || lo > hi || lo < 0x100) {
		reply_sa(fd, m, EINVAL, NULL);
		return;
	}
	/* Random SPI within the range: sequential allocation from a fixed seed
	 * makes SPIs predictable and (across peers) colliding.  getrandom is
	 * available on Linux; fall back to a time/pid mix elsewhere.
	 * NOTE (L7): hi-lo+1 overflows to 0 for the full 32-bit range, so bound
	 * the tries by the span only when it fits, else by UINT32_MAX. */
	{
		uint64_t span64 = (uint64_t)hi - (uint64_t)lo + 1;
		uint32_t span = span64 > UINT32_MAX ? UINT32_MAX : (uint32_t)span64;
		for (uint32_t tries = 0, lim = span ? span : UINT32_MAX;
		    tries < lim; tries++) {
		struct r2dp_sa k = *rq;
		uint32_t r;
		if (getrandom(&r, sizeof(r), 0) != (ssize_t)sizeof(r))
			r = (uint32_t)((uint64_t)time(NULL) ^ (uint64_t)getpid()
			    ^ (uint64_t)(uintptr_t)&r ^ (uintptr_t)m);
		cand = lo + (uint32_t)((uint64_t)r % span64);
		k.spi = htonl(cand);
		if (sa_find(C, &k))
			continue;
		if ((idx = sa_alloc_idx(C)) < 0) { reply_sa(fd, m, ENOBUFS, NULL); return; }
		e = &C->sad[idx];
		memset(e, 0, sizeof(*e));
		e->used = e->larval = 1;
		e->larva_at = time(NULL);
		e->sa = *rq;
		e->sa.spi = htonl(cand);
		reply_sa(fd, m, 0, e);
		return;
		}
	}
	reply_sa(fd, m, ENOSPC, NULL);
}

/* soft/hard TIME and BYTE lifetime expiry -> unsolicited EXPIRE to every client
 * (racoon2's cb_expire hunts the SAD by SPI and rekeys).  The forwarder is the
 * SAD source of truth; the threshold resets on each reinstantiation.  TIME is
 * tracked here (available to every backend); BYTE needs a per-SA counter in the
 * dataplane and is skipped when the backend offers no ->sa_bytes (0 is
 * "infinite").  Notify flags are shared per level: whichever threshold (time or
 * bytes) trips first for soft/hard fires the one EXPIRE. */
static void
check_lifetimes(const int *cli, int ncli)
{
	time_t now = time(NULL);
	for (int i = 0; i < FWD_MAXSA; i++) {
		struct fwd_sa_ent *e = &C->sad[i];
		uint64_t el, soft_t, hard_t, soft_b, hard_b;
		int64_t nbytes = -1;
		struct r2dp_sa sp;
		char stale;

		if (!e->used || e->larval || !e->installed_at)
			continue;
		el = (uint64_t)(now - e->installed_at);
		soft_t = e->sa.lft_soft_time;
		hard_t = e->sa.lft_hard_time;
		soft_b = e->sa.lft_soft_bytes;
		hard_b = e->sa.lft_hard_bytes;
		/* byte lifetimes: read the dataplane's counter keyed by this SA.
		 * ctl's repo keeps spi network-order; the dp keys on host spi and
		 * raw-wire dip bytes (addr4_to_u32 memcpy). */
		if ((soft_b || hard_b) && C->dp.ops && C->dp.ops->sa_bytes) {
			uint32_t hspi = ntohl(e->sa.spi);
			uint32_t ndip;
			memcpy(&ndip, &e->sa.dst.addr, 4);
			nbytes = C->dp.ops->sa_bytes(&C->dp, hspi, ndip);
		}
		stale = 0;
		/* hard expiry just fires (once); racoon2 dislikes a second one for
		 * an SA already teared down.  We tear it out of the SAD here. */
		if (hard_t && el >= hard_t && !e->hard_notified) {
			e->hard_notified = 1; e->soft_notified = 1;
			sp = e->sa; sp.expired = 2; stale = 1;
		} else if (hard_b && nbytes >= 0 &&
		    (uint64_t)nbytes >= hard_b && !e->hard_notified) {
			e->hard_notified = 1; e->soft_notified = 1;
			sp = e->sa; sp.expired = 2; stale = 1;
		} else if (soft_t && el >= soft_t && !e->soft_notified) {
			e->soft_notified = 1;
			sp = e->sa; sp.expired = 1;
		} else if (soft_b && nbytes >= 0 &&
		    (uint64_t)nbytes >= soft_b && !e->soft_notified) {
			e->soft_notified = 1;
			sp = e->sa; sp.expired = 1;
		} else {
			continue;
		}
		for (int c = 0; c < ncli; c++)
			csend(cli[c], R2DP_EXPIRE, 0, 0, R2DP_HF_NOKEYS,
			    &sp, sizeof(sp), NULL, 0);
		if (stale) {
			/* hard expiry: withdraw the SA from the dataplane too */
			(void)sa_apply_dp(C, 0, &e->sa, NULL, 0);
			e->used = 0; e->installed_at = 0;
		}
	}
}

/* Reap larval (GETSPI-reserved, never confirmed) SAs past their TTL. */
static void
reap_larv(void)
{
	time_t now = time(NULL);

	for (int i = 0; i < FWD_MAXSA; i++)
		if (C->sad[i].used && C->sad[i].larval &&
		    now - C->sad[i].larva_at > R2DP_LARVAL_TTL_S)
			C->sad[i].used = 0;
}

/* SA direction: the explicit v2 r2dp_sa.dir wins; with dir unspecified
 * fall back to the v1 inference (an SA completing our GETSPI reservation, or
 * one already known inbound, protects traffic TO us). */
static int
sa_is_inbound(const struct fwd_sa_ent *e, const struct r2dp_sa *rq)
{
	if (rq->dir == R2DP_DIR_IN)
		return 1;
	if (rq->dir == R2DP_DIR_OUT)
		return 0;
	return e && (e->larval || e->inbound);
}

static void
do_sa(int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sa *rq = r2dp_msg_sa(m);
	struct fwd_sa_ent *e = sa_find(C, rq);
	uint8_t blob[R2DP_MAX_KEY];
	size_t blen = 0;
	int rc = 0;

	if (!(m->h.flags & R2DP_HF_NOKEYS)) {
		/* reconstruct the AEAD/enc key blob for the dataplane */
		size_t el = rq->enckeylen, al = rq->authkeylen;
		if (el + al > sizeof(blob)) { rc = EINVAL; goto out; }
		memcpy(blob, r2dp_msg_enckey(m), el);
		if (al)
			memcpy(blob + el, r2dp_msg_authkey(m), al);
		blen = el + al;
	}

	switch (m->h.type) {
	case R2DP_SA_ADD:
		if (e && !e->larval) { rc = EEXIST; goto out; }
		if (!e) {
			int i = sa_alloc_idx(C);
			if (i < 0) { rc = ENOBUFS; goto out; }
			e = &C->sad[i];
			memset(e, 0, sizeof(*e));
			e->used = 1;
		}
		{
			/* An SA completing our GETSPI reservation (a larval we handed out)
			 * protects traffic TO us: seed the dataplane with the INBOUND flag.
			 * The flag stays sticky across UPDATE (e->inbound). */
			int flags = 1 | (sa_is_inbound(e, rq) ? FWD_DP_SA_INBOUND : 0);
			int dperr = sa_apply_dp(C, flags, rq, blen ? blob : NULL, blen);
			if (dperr) {
				/* Roll back the ctl entry on dp failure.  If this was a
				 * GETSPI larval reservation, keep it reserved; otherwise
				 * free the slot. */
				if (!e->larval)
					e->used = 0;
				rc = dp_errno(dperr);
				goto out;
			}
		}
		/* commit: promotes a larval reservation to a live SA */
		e->inbound = sa_is_inbound(e, rq);
		e->larval = 0;
		e->sa = *rq;
		/* restart the lifetime clock on (re)install */
		e->installed_at = time(NULL);
		e->soft_notified = e->hard_notified = 0;
		goto out_ok;
	case R2DP_SA_UPDATE:
		if (!e) { rc = ENOENT; goto out; }
		/* M1: an in-place UPDATE that carries key material on a LIVE
		 * (non-larval) SA would rebuild the rte_ipsec_sa with sqn=0,
		 * repeating sequence numbers / GCM nonces under a reused key --
		 * catastrophic for GCM (IV reuse).  racoon2 rekeys with a fresh SPI
		 * (new slot), so refuse instead of corrupting replay/nonce state.
		 * A larval UPDATE (the GETSPI completion path) is fine: it installs
		 * the key for the first time.  Lifetime-only updates carry no blob. */
		if (!e->larval && blen) { rc = EINVAL; goto out; }
		{
			/* Apply to the dataplane FIRST.  The dataplane's update is
			 * del-then-add, so on failure the SAD holds nothing while the
			 * ctl table still holds the old SA -- reconcile by reverting the
			 * ctl entry only if we had the old state.  We keep e->sa as the
			 * last known-good so GET after a failed update is consistent.
			 * racoon2 UPDATEs the larval SA it GETSPI'd: that is the inbound
			 * SA.  An UPDATE of a live SA keeps its direction (e->inbound). */
			int flags = 1 | (sa_is_inbound(e, rq) ? FWD_DP_SA_INBOUND : 0);
			/* A lifetime-only UPDATE of a live SA (no key tail) changes
			 * nothing the dataplane holds -- lifetimes are enforced here
			 * -- so it must not rebuild the dataplane SA (which needs the
			 * key and would reset sequence/replay state). */
			int dperr = (e->larval || blen) ?
			    sa_apply_dp(C, flags, rq, blen ? blob : NULL, blen) : 0;
			if (dperr) {
				/* e->sa was not touched: the ctl entry still reflects the
				 * last-known-good SA, consistent with the dataplane which
				 * either kept the old entry or rolled back its del-then-add. */
				rc = dp_errno(dperr);
				goto out;
			}
		}
		e->inbound = sa_is_inbound(e, rq);
		/* The lifetime clock starts when key material is installed (the
		 * larval promotion).  A lifetime-only UPDATE of a live SA must not
		 * restart it, or repeated UPDATEs would keep an SA alive forever;
		 * new thresholds apply against the original install time. */
		if (e->larval) {
			e->installed_at = time(NULL);
			e->soft_notified = e->hard_notified = 0;
		}
		e->larval = 0; e->sa = *rq;
		goto out_ok;
	case R2DP_SA_DEL:
		if (!e) { rc = ENOENT; goto out; }
		{
			int dperr = sa_apply_dp(C, 0, rq, NULL, 0);
			if (dperr) {
				/* dataplane still owns the SA; keep the ctl entry live */
				rc = dp_errno(dperr);
				goto out;
			}
		}
		reply_sa(fd, m, 0, e);
		e->used = 0;
		goto scrub;
	case R2DP_SA_GET:
		if (!e || e->larval) { rc = ENOENT; goto out; }
		reply_sa(fd, m, 0, e);
		goto scrub;
	case R2DP_SA_DUMP: {
		/* Stream every live SA back as one SA_DUMP message each, MORE set
		 * on all but the last -- mirrors SP_DUMP so r2dpctl can enumerate
		 * the SAD and verify the dataplane matches.  Completing-reply type
		 * is the request type (R2DP_SA_DUMP); each carries its own seq. */
		int last = -1;
		for (int i = 0; i < FWD_MAXSA; i++)
			if (C->sad[i].used && !C->sad[i].larval) last = i;
		if (last < 0) { rc = ENOENT; goto out; }
		for (int i = 0; i <= last; i++) {
			if (!C->sad[i].used || C->sad[i].larval) continue;
			int more = 0;
			for (int j = i + 1; j <= last; j++)
				if (C->sad[j].used && !C->sad[j].larval) { more = 1; break; }
			reply_sa_dump(fd, m, 0, &C->sad[i].sa,
			    more ? R2DP_HF_MORE : 0);
		}
		goto out; }
	default:
		rc = ENOSYS;
		goto out;
	}

out_ok:
	reply_sa(fd, m, 0, e);
	goto scrub;
out:
	reply_sa(fd, m, rc, NULL);
scrub:
	/* M7: scrub the reconstructed key blob on EVERY exit, success or error,
	 * so key material never lingers on the stack. */
	explicit_bzero(blob, sizeof(blob));
}

/* Selector prefix lengths must fit the address family. */
static int
sp_valid(const struct r2dp_sp *sp)
{
	const struct { const struct r2dp_addr *a; uint8_t p; } chk[] = {
		{ &sp->sel_src, sp->pref_src }, { &sp->sel_dst, sp->pref_dst },
	};

	for (unsigned i = 0; i < 2; i++) {
		unsigned max = chk[i].a->family == R2DP_AF_INET4 ? 32 :
		    chk[i].a->family == R2DP_AF_INET6 ? 128 : 0;
		if (chk[i].p > max)
			return EINVAL;
	}
	return 0;
}

/* Next forwarder-assigned slid: never 0, never one already in use (the
 * counter may wrap).  0 if the space is exhausted. */
static uint32_t
slid_alloc(struct fwd_ctl *c)
{
	for (uint32_t tries = 0; tries < FWD_MAXSP + 1; tries++) {
		uint32_t s = c->next_slid++;
		struct r2dp_sp k;
		if (s == 0)
			continue;
		memset(&k, 0, sizeof(k));
		k.slid = s;
		if (!sp_find(c, &k, 0))
			return s;
	}
	return 0;
}

static void
do_sp(int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sp *rq = r2dp_msg_sp(m);
	struct fwd_sp_ent *e;
	struct r2dp_sp out;

	switch (m->h.type) {
	case R2DP_SP_ADD: {
		struct fwd_sp_ent prev;
		int rc = sp_valid(rq);

		if (rc) { reply_sp(fd, m, rc, rq, 0); return; }
		e = sp_find(C, rq, 1);
		if (e && !(rq->flags & R2DP_SPF_UPDATE)) {
			reply_sp(fd, m, EEXIST, rq, 0);
			return;
		}
		/* a client-chosen slid must not alias a different policy */
		if (rq->slid) {
			struct fwd_sp_ent *o = sp_find(C, rq, 0);
			if (o && o != e) { reply_sp(fd, m, EEXIST, rq, 0); return; }
		}
		if (!e) {
			int i;
			for (i = 0; i < FWD_MAXSP; i++)
				if (!C->spd[i].used) break;
			if (i == FWD_MAXSP) { reply_sp(fd, m, ENOBUFS, rq, 0); return; }
			e = &C->spd[i];
			out = *rq; out.slid = rq->slid ? rq->slid : slid_alloc(C);
			if (!out.slid) { reply_sp(fd, m, ENOBUFS, rq, 0); return; }
		} else {
			out = *rq; out.slid = e->sp.slid;
		}
		out.flags &= ~R2DP_SPF_UPDATE;
		prev = *e;
		if (C->dp.ops && C->dp.ops->sp_add) {
			int derr = C->dp.ops->sp_add(&C->dp, &out);
			if (derr) {
				/* Don't commit a policy the dataplane refused.  An upsert
				 * keeps the previous policy (the dataplane still holds it);
				 * a new add leaves the slot free. */
				*e = prev;
				reply_sp(fd, m, dp_errno(derr), rq, 0);
				return;
			}
		}
		e->used = 1;
		e->sp = out;
		reply_sp(fd, m, 0, &out, 0);
		return; }
	case R2DP_SP_DEL:
		e = rq->slid ? sp_find(C, rq, 0) : sp_find(C, rq, 1);
		if (!e) { reply_sp(fd, m, ENOENT, rq, 0); return; }
		out = e->sp;
		if (C->dp.ops && C->dp.ops->sp_del) {
			int derr = C->dp.ops->sp_del(&C->dp, &out);
			if (derr) {
				reply_sp(fd, m, dp_errno(derr), &out, 0);
				return;   /* keep the ctl entry: dataplane still holds it */
			}
		}
		e->used = 0;
		reply_sp(fd, m, 0, &out, 0);
		return;
	case R2DP_SP_GET:
		e = sp_find(C, rq, 0);
		if (!e) { reply_sp(fd, m, ENOENT, rq, 0); return; }
		reply_sp(fd, m, 0, &e->sp, 0);
		return;
	case R2DP_SP_DUMP: {
		int last = -1;
		for (int i = 0; i < FWD_MAXSP; i++)
			if (C->spd[i].used) last = i;
		if (last < 0) { reply_sp(fd, m, ENOENT, rq, 0); return; }
		for (int i = 0; i <= last; i++)
			if (C->spd[i].used) {
				int more = 0;
				for (int j = i + 1; j <= last; j++)
					if (C->spd[j].used) { more = 1; break; }
				reply_sp(fd, m, 0, &C->spd[i].sp, more ? R2DP_HF_MORE : 0);
			}
		return; }
	}
}

static void
dispatch(int fd, const struct r2dp_msg *m)
{
	switch (m->h.type) {
	case R2DP_HELLO:  do_hello(fd, m); break;
	case R2DP_GETSPI: do_getspi(fd, m); break;
	case R2DP_SA_ADD: case R2DP_SA_UPDATE: case R2DP_SA_DEL: case R2DP_SA_GET:
	case R2DP_SA_DUMP:
		do_sa(fd, m); break;
	case R2DP_SP_ADD: case R2DP_SP_DEL: case R2DP_SP_GET: case R2DP_SP_DUMP:
		do_sp(fd, m); break;
	default:
		csend(fd, m->h.type, m->h.seq, EPROTO, m->h.flags | R2DP_HF_NOKEYS,
		    m->body, m->h.len - sizeof(m->h), NULL, 0);
	}
}

int
fwd_ctl_init(struct fwd_ctl *c, const char *sockpath, int verbose)
{
	memset(c, 0, sizeof(*c));
	C = c;
	(void)sockpath;   /* socket path is used by fwd_ctl_run */
	g_stop = 0;
	signal(SIGTERM, on_sig);
	signal(SIGINT, on_sig);
	signal(SIGPIPE, SIG_IGN);
	c->verbose = verbose;
	c->next_slid = 1;
	c->epoch = ((uint64_t)time(NULL) << 20) ^ (uint64_t)getpid();
	fwd_dp_init(&c->dp);       /* no-op without a registered backend */
	return 0;
}

/* Verify the connecting peer is the socket owner (the forwarder's euid).
 * Defense-in-depth on top of the 0600 socket mode: reject a peer whose real
 * uid differs.  SO_PEERCRED is Linux; elsewhere accept any same-uid peer. */
static int
peer_allowed(int fd)
{
#ifdef SO_PEERCRED
	struct ucred uc;
	socklen_t len = sizeof(uc);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) == 0)
		return uc.uid == geteuid();
	/* couldn't read creds: err on the side of rejecting */
	return 0;
#else
	return 1;
#endif
}

int
fwd_ctl_run(struct fwd_ctl *c, const char *sockpath)
{
	int lfd = r2dp_listen(sockpath, 8);
	struct pollfd pf[MAXCLI + 1];
	int ncli = 0, cli[MAXCLI];

	if (lfd < 0) {
		fprintf(stderr, "r2dp: listen %s: %s\n", sockpath, strerror(-lfd));
		return -1;
	}
	fprintf(stderr, "r2dp: serving %s (epoch=%llu)\n", sockpath,
	    (unsigned long long)c->epoch);
	for (;;) {
		int n = 0, r, npoll;   /* npoll = clients we polled this pass */
		if (g_stop)
			break;
		reap_larv();          /* expire stale GETSPI reservations */
		check_lifetimes(cli, ncli);  /* soft/hard TIME expiry -> EXPIRE */
		npoll = ncli;
		pf[n].fd = lfd; pf[n++].events = POLLIN;
		for (int i = 0; i < ncli; i++) { pf[n].fd = cli[i]; pf[n++].events = POLLIN; }
		if (poll(pf, n, 500) < 0) { if (errno == EINTR) continue; break; }
		if (pf[0].revents & POLLIN) {
			int fd = r2dp_accept(lfd);
			if (fd >= 0 && ncli < MAXCLI && peer_allowed(fd) &&
			    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0)
				cli[ncli++] = fd;
			else if (fd >= 0) {
				fprintf(stderr, "r2dp: refused peer (uid check)\n");
				close(fd);
			}
		}
		/* Process the clients that were actually polled this pass (up to
		 * npoll).  An accept above appended cli[npoll] and bumped ncli, but
		 * pf[] was built for the OLD count -- iterating to the new ncli
		 * would read an unbuilt/stale pf[i+1].revents (which may carry
		 * POLLIN) and drive a BLOCKING r2dp_recv on a fresh idle fd,
		 * freezing the control loop.  The just-accepted fd is serviced on
		 * the next poll pass.  Defer removals until after the pass so the
		 * pf[] revents stay aligned with cli[] (M6). */
		for (int i = 0; i < npoll; i++) {
			struct r2dp_msg m;
			if (!(pf[i + 1].revents & (POLLIN | POLLHUP | POLLERR))) continue;
			r = r2dp_recv(cli[i], &m);
			if (r == 0)
				dispatch(cli[i], &m);
			/* the receive buffer may carry SA keys: scrub it */
			explicit_bzero(&m, sizeof(m));
			if (r == 0)
				continue;
			close(cli[i]); cli[i] = -1;   /* mark for removal */
		}
		/* drop clients whose sends would block or failed (this pass,
		 * including the EXPIRE broadcast before poll) */
		for (int i = 0; i < ncli; i++)
			if (cli[i] >= 0 && is_bad(cli[i])) {
				fprintf(stderr, "r2dp: dropped slow/dead client fd=%d\n",
				    cli[i]);
				close(cli[i]);
				cli[i] = -1;
			}
		nbad = 0;
		/* compact out the -1 slots */
		{
			int w = 0;
			for (int i = 0; i < ncli; i++)
				if (cli[i] >= 0)
					cli[w++] = cli[i];
			ncli = w;
		}
	}
	/* stop the dataplane worker threads on the way out (M4) */
	if (C->dp.ops && C->dp.ops->stop)
		C->dp.ops->stop(&C->dp);
	return 0;
}

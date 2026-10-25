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

/* ----------------------------------------------------------- reply */
static int
reply_sa(int fd, const struct r2dp_msg *req, int status,
    const struct fwd_sa_ent *e)
{
	const struct r2dp_sa *sa = e ? &e->sa : r2dp_msg_sa(req);
	return r2dp_send(fd, req->h.type, req->h.seq, status, R2DP_HF_NOKEYS,
	    sa, sizeof(*sa), NULL, 0);
}

static int
reply_sp(int fd, const struct r2dp_msg *req, int status,
    const struct r2dp_sp *sp, uint32_t flags)
{
	return r2dp_send(fd, req->h.type, req->h.seq, status, flags,
	    sp, sizeof(*sp), NULL, 0);
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
	/* Advertise only what the dataplane actually implements.  ESN is
	 * plumbed through the SA; NAT-T, IPv6 and EXPIRE are not yet wired, so
	 * they must not be advertised or racoon2 would negotiate them and fail. */
	a.features = R2DP_FEAT_ESN;
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
	r2dp_send(fd, R2DP_HELLO_ACK, m->h.seq, 0, 0, &a, sizeof(a), NULL, 0);
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

	if (rq->dst.family == R2DP_AF_UNSET || lo > hi) {
		reply_sa(fd, m, EINVAL, NULL);
		return;
	}
	/* Random SPI within the range: sequential allocation from a fixed seed
	 * makes SPIs predictable and (across peers) colliding.  getrandom is
	 * available on Linux; fall back to a time/pid mix elsewhere. */
	for (uint32_t tries = 0, span = hi - lo + 1; tries < span; tries++) {
		struct r2dp_sa k = *rq;
		uint32_t r;
		if (getrandom(&r, sizeof(r), 0) != (ssize_t)sizeof(r))
			r = (uint32_t)((uint64_t)time(NULL) ^ (uint64_t)getpid()
			    ^ (uint64_t)(uintptr_t)&r ^ (uintptr_t)m);
		cand = lo + (r % span);
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
	reply_sa(fd, m, ENOSPC, NULL);
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

static void
do_sa(int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sa *rq = r2dp_msg_sa(m);
	struct fwd_sa_ent *e = sa_find(C, rq);
	uint8_t blob[R2DP_MAX_KEY];
	size_t blen = 0;

	if (!(m->h.flags & R2DP_HF_NOKEYS)) {
		/* reconstruct the AEAD/enc key blob for the dataplane */
		size_t el = rq->enckeylen, al = rq->authkeylen;
		if (el + al > sizeof(blob)) { reply_sa(fd, m, EINVAL, NULL); return; }
		memcpy(blob, r2dp_msg_enckey(m), el);
		if (al)
			memcpy(blob + el, r2dp_msg_authkey(m), al);
		blen = el + al;
	}

	switch (m->h.type) {
	case R2DP_SA_ADD:
		if (e && !e->larval) { reply_sa(fd, m, EEXIST, NULL); return; }
		if (!e) {
			int i = sa_alloc_idx(C);
			if (i < 0) { reply_sa(fd, m, ENOBUFS, NULL); return; }
			e = &C->sad[i];
			memset(e, 0, sizeof(*e));
			e->used = 1;
		}
		{
			/* An SA completing our GETSPI reservation (a larval we handed out)
			 * protects traffic TO us: seed the dataplane with the INBOUND flag.
			 * The flag stays sticky across UPDATE (e->inbound). */
			int flags = 1 | ((e->larval || e->inbound) ? FWD_DP_SA_INBOUND : 0);
			int dperr = sa_apply_dp(C, flags, rq, blen ? blob : NULL, blen);
			if (dperr) {
				/* Roll back the ctl entry on dp failure.  If this was a
				 * GETSPI larval reservation, keep it reserved; otherwise
				 * free the slot. */
				if (!e->larval)
					e->used = 0;
				reply_sa(fd, m, dperr, NULL);
				return;
			}
		}
		/* commit: promotes a larval reservation to a live SA */
		if (e->larval)
			e->inbound = 1;
		e->larval = 0;
		e->sa = *rq;
		explicit_bzero(blob, sizeof(blob));   /* scrub key material (L5) */
		reply_sa(fd, m, 0, e);
		return;
	case R2DP_SA_UPDATE:
		if (!e) { reply_sa(fd, m, ENOENT, NULL); return; }
		/* M1: an in-place UPDATE that carries key material on a LIVE
		 * (non-larval) SA would rebuild the rte_ipsec_sa with sqn=0,
		 * repeating sequence numbers / GCM nonces under a reused key --
		 * catastrophic for GCM (IV reuse).  racoon2 rekeys with a fresh SPI
		 * (new slot), so refuse instead of corrupting replay/nonce state.
		 * A larval UPDATE (the GETSPI completion path) is fine: it installs
		 * the key for the first time.  Lifetime-only updates carry no blob. */
		if (!e->larval && blen)
			{ reply_sa(fd, m, EINVAL, NULL); return; }
		{
			/* Apply to the dataplane FIRST.  The dataplane's update is
			 * del-then-add, so on failure the SAD holds nothing while the
			 * ctl table still holds the old SA -- reconcile by reverting the
			 * ctl entry only if we had the old state.  We keep e->sa as the
			 * last known-good so GET after a failed update is consistent.
			 * racoon2 UPDATEs the larval SA it GETSPI'd: that is the inbound
			 * SA.  An UPDATE of a live SA keeps its direction (e->inbound). */
			int flags = 1 | ((e->larval || e->inbound) ?
			    FWD_DP_SA_INBOUND : 0);
			int dperr = sa_apply_dp(C, flags, rq, blen ? blob : NULL, blen);
			if (dperr) {
				/* e->sa was not touched: the ctl entry still reflects the
				 * last-known-good SA, consistent with the dataplane which
				 * either kept the old entry or rolled back its del-then-add. */
				reply_sa(fd, m, dperr, NULL);
				return;
			}
		}
		if (e->larval)
			e->inbound = 1;
		e->larval = 0; e->sa = *rq;
		explicit_bzero(blob, sizeof(blob));   /* scrub key material (L5) */
		reply_sa(fd, m, 0, e);
		return;
	case R2DP_SA_DEL:
		if (!e) { reply_sa(fd, m, ENOENT, NULL); return; }
		{
			int dperr = sa_apply_dp(C, 0, rq, NULL, 0);
			if (dperr) {
				/* dataplane still owns the SA; keep the ctl entry live */
				reply_sa(fd, m, dperr, NULL);
				return;
			}
		}
		reply_sa(fd, m, 0, e);
		e->used = 0;
		return;
	case R2DP_SA_GET:
		if (!e || e->larval) { reply_sa(fd, m, ENOENT, NULL); return; }
		reply_sa(fd, m, 0, e);
		return;
	}
}

static void
do_sp(int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sp *rq = r2dp_msg_sp(m);
	struct fwd_sp_ent *e;
	struct r2dp_sp out;

	switch (m->h.type) {
	case R2DP_SP_ADD:
		e = sp_find(C, rq, 1);
		if (e && !(rq->flags & R2DP_SPF_UPDATE)) {
			reply_sp(fd, m, EEXIST, rq, 0);
			return;
		}
		if (!e) {
			int i;
			for (i = 0; i < FWD_MAXSP; i++)
				if (!C->spd[i].used) break;
			if (i == FWD_MAXSP) { reply_sp(fd, m, ENOBUFS, rq, 0); return; }
			e = &C->spd[i];
			e->used = 1;
			out = *rq; out.slid = rq->slid ? rq->slid : C->next_slid++;
		} else {
			out = *rq; out.slid = e->sp.slid;
		}
		out.flags &= ~R2DP_SPF_UPDATE;
		e->sp = out;
		if (C->dp.ops && C->dp.ops->sp_add) {
			int derr = C->dp.ops->sp_add(&C->dp, &out);
			if (derr) {
				/* don't commit a policy the dataplane refused */
				e->used = 0;
				reply_sp(fd, m, derr, rq, 0);
				return;
			}
		}
		reply_sp(fd, m, 0, &out, 0);
		return;
	case R2DP_SP_DEL:
		e = rq->slid ? sp_find(C, rq, 0) : sp_find(C, rq, 1);
		if (!e) { reply_sp(fd, m, ENOENT, rq, 0); return; }
		out = e->sp;
		if (C->dp.ops && C->dp.ops->sp_del) {
			int derr = C->dp.ops->sp_del(&C->dp, &out);
			if (derr) {
				reply_sp(fd, m, derr, &out, 0);
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
		do_sa(fd, m); break;
	case R2DP_SP_ADD: case R2DP_SP_DEL: case R2DP_SP_GET: case R2DP_SP_DUMP:
		do_sp(fd, m); break;
	default:
		r2dp_send(fd, m->h.type, m->h.seq, EPROTO, m->h.flags | R2DP_HF_NOKEYS,
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
		int n = 0, r;
		if (g_stop)
			break;
		reap_larv();          /* expire stale GETSPI reservations */
		pf[n].fd = lfd; pf[n++].events = POLLIN;
		for (int i = 0; i < ncli; i++) { pf[n].fd = cli[i]; pf[n++].events = POLLIN; }
		if (poll(pf, n, 500) < 0) { if (errno == EINTR) continue; break; }
		if (pf[0].revents & POLLIN) {
			int fd = r2dp_accept(lfd);
			if (fd >= 0 && ncli < MAXCLI && peer_allowed(fd))
				cli[ncli++] = fd;
			else if (fd >= 0) {
				fprintf(stderr, "r2dp: refused peer (uid check)\n");
				close(fd);
			}
		}
		/* Process ready clients, deferring removals until after the pass so
		 * the pf[] revents stay aligned with cli[] (M6): removing a client
		 * mid-loop both skips other ready fds and desyncs pf[]. */
		for (int i = 0; i < ncli; i++) {
			struct r2dp_msg m;
			if (!(pf[i + 1].revents & (POLLIN | POLLHUP | POLLERR))) continue;
			r = r2dp_recv(cli[i], &m);
			if (r == 0) { dispatch(cli[i], &m); continue; }
			close(cli[i]); cli[i] = -1;   /* mark for removal */
		}
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

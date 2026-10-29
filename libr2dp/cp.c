#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "r2dp/cp.h"

#define MAXSA  1024
#define MAXSP  1024
#define MAXCLI 16

struct sa_ent { int used, larval, soft_sent; struct r2dp_sa sa;
                uint8_t enc[R2DP_MAX_KEY], auth[R2DP_MAX_KEY];
                uint64_t added_mono, added_wall; };
struct sp_ent { int used; struct r2dp_sp sp; };

struct r2dp_cp {
	struct r2dp_cp_hooks h;
	struct r2dp_cp_caps caps;
	struct r2dp_cp_opts o;
	char name[32];
	uint64_t epoch;
	uint32_t next_spi, next_slid;
	struct sa_ent sad[MAXSA];
	struct sp_ent spd[MAXSP];
	struct { int fd; uint32_t role; } cli[MAXCLI];   /* clients that completed HELLO */
	unsigned ncli;
	uint64_t ev_sent, ev_dropped;
};

static uint64_t mono_s(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec;
}

#define LOG(cp, ...) do { if ((cp)->o.verbose) { fprintf(stderr, "%s: ", (cp)->name); \
	fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

struct r2dp_cp *r2dp_cp_new(const struct r2dp_cp_hooks *h, const struct r2dp_cp_caps *caps,
                            const struct r2dp_cp_opts *opts)
{
	struct r2dp_cp *cp = calloc(1, sizeof(*cp));
	if (!cp) return NULL;
	if (h) cp->h = *h;
	if (caps) cp->caps = *caps;
	else {
		cp->caps.features = R2DP_FEAT_ESN | R2DP_FEAT_NATT | R2DP_FEAT_IPV6 | R2DP_FEAT_EXPIRE;
		memset(cp->caps.enc_caps, 0xff, sizeof(cp->caps.enc_caps));
		memset(cp->caps.integ_caps, 0xff, sizeof(cp->caps.integ_caps));
	}
	if (opts) cp->o = *opts;
	snprintf(cp->name, sizeof(cp->name), "%s", cp->o.name ? cp->o.name : "r2dp-cp");
	cp->epoch = ((uint64_t)time(NULL) << 20) ^ (uint64_t)getpid();
	cp->next_spi = 0x100; cp->next_slid = 1;
	return cp;
}
void r2dp_cp_free(struct r2dp_cp *cp) { free(cp); }

/* ------------------------------------------------------------------ SAD */
static struct sa_ent *sa_find(struct r2dp_cp *cp, const struct r2dp_sa *k)
{
	for (int i = 0; i < MAXSA; i++)
		if (cp->sad[i].used && cp->sad[i].sa.spi == k->spi && cp->sad[i].sa.proto == k->proto &&
		    r2dp_addr_eq(&cp->sad[i].sa.dst, &k->dst))
			return &cp->sad[i];
	return NULL;
}
static struct sa_ent *sa_alloc(struct r2dp_cp *cp)
{
	for (int i = 0; i < MAXSA; i++) if (!cp->sad[i].used) return &cp->sad[i];
	return NULL;
}
static void sa_store(struct sa_ent *e, const struct r2dp_msg *m)
{
	const struct r2dp_sa *sa = r2dp_msg_sa(m);
	e->sa = *sa;
	memset(e->enc, 0, sizeof(e->enc)); memset(e->auth, 0, sizeof(e->auth));
	if (!(m->h.flags & R2DP_HF_NOKEYS)) {
		memcpy(e->enc, r2dp_msg_enckey(m), sa->enckeylen);
		memcpy(e->auth, r2dp_msg_authkey(m), sa->authkeylen);
	}
}

/* ------------------------------------------------------------------ SPD */
static int sel_eq(const struct r2dp_sp *a, const struct r2dp_sp *b)
{
	return a->dir == b->dir && a->ul_proto == b->ul_proto &&
	       a->pref_src == b->pref_src && a->pref_dst == b->pref_dst &&
	       r2dp_addr_eq(&a->sel_src, &b->sel_src) && a->sel_src.port == b->sel_src.port &&
	       r2dp_addr_eq(&a->sel_dst, &b->sel_dst) && a->sel_dst.port == b->sel_dst.port;
}
static struct sp_ent *sp_find(struct r2dp_cp *cp, const struct r2dp_sp *k, int by_selector)
{
	for (int i = 0; i < MAXSP; i++) {
		if (!cp->spd[i].used) continue;
		if (by_selector ? sel_eq(&cp->spd[i].sp, k) : cp->spd[i].sp.slid == k->slid)
			return &cp->spd[i];
	}
	return NULL;
}

/* ------------------------------------------------------------- replying */
static int reply_sa(struct r2dp_cp *cp, int fd, const struct r2dp_msg *req, int status,
                    const struct sa_ent *e)
{
	const struct r2dp_sa *sa = e ? &e->sa : r2dp_msg_sa(req);
	uint8_t tail[2 * R2DP_MAX_KEY];
	size_t tl = 0;
	uint32_t fl = R2DP_HF_NOKEYS;

	if (e && cp->o.echo_keys && !status) {
		memcpy(tail, e->enc, sa->enckeylen);
		memcpy(tail + sa->enckeylen, e->auth, sa->authkeylen);
		tl = (size_t)sa->enckeylen + sa->authkeylen;
		fl = 0;
	}
	return r2dp_send(fd, req->h.type, req->h.seq, status, fl, sa, sizeof(*sa), tail, tl);
}
static int reply_sp(int fd, const struct r2dp_msg *req, int status,
                    const struct r2dp_sp *sp, uint32_t flags)
{
	return r2dp_send(fd, req->h.type, req->h.seq, status, flags, sp, sizeof(*sp), NULL, 0);
}

static void log_sa(struct r2dp_cp *cp, const char *op, const struct r2dp_sa *s)
{
	char d[INET6_ADDRSTRLEN] = "?";
	if (!cp->o.verbose) return;
	if (s->dst.family == R2DP_AF_INET4) inet_ntop(AF_INET, s->dst.addr, d, sizeof(d));
	else if (s->dst.family == R2DP_AF_INET6) inet_ntop(AF_INET6, s->dst.addr, d, sizeof(d));
	LOG(cp, "%s spi=0x%08x dst=%s proto=%u enc=%u integ=%u esn=%u natt=%u/%u enclen=%u authlen=%u reqid=%u",
	    op, ntohl(s->spi), d, s->proto, s->enc, s->integ, !!(s->saflags & R2DP_SAF_ESN),
	    s->natt_type, ntohs(s->natt_dport), s->enckeylen, s->authkeylen, s->reqid);
}

/* ------------------------------------------------------------- handlers */
static void do_hello(struct r2dp_cp *cp, int fd, const struct r2dp_msg *m)
{
	struct r2dp_hello_ack a;
	const struct r2dp_hello *h = (const void *)m->body;
	memset(&a, 0, sizeof(a));
	a.epoch = cp->epoch; a.max_msg = R2DP_MAX_MSG; a.features = cp->caps.features;
	memcpy(a.enc_caps, cp->caps.enc_caps, sizeof(a.enc_caps));
	memcpy(a.integ_caps, cp->caps.integ_caps, sizeof(a.integ_caps));
	LOG(cp, "HELLO role=%u pid=%u", h->role, h->pid);
	{
		unsigned i;
		for (i = 0; i < cp->ncli; i++) if (cp->cli[i].fd == fd) break;
		if (i < MAXCLI) { cp->cli[i].fd = fd; cp->cli[i].role = h->role; if (i == cp->ncli) cp->ncli++; }
	}
	r2dp_send(fd, R2DP_HELLO_ACK, m->h.seq, 0, 0, &a, sizeof(a), NULL, 0);
}

static void do_getspi(struct r2dp_cp *cp, int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sa *rq = r2dp_msg_sa(m);
	uint32_t lo = rq->spi_min ? rq->spi_min : 0x100;
	uint32_t hi = rq->spi_max ? rq->spi_max : 0x0fffffff;
	struct sa_ent *e;

	log_sa(cp, "GETSPI", rq);
	if (rq->dst.family == R2DP_AF_UNSET || lo > hi) { reply_sa(cp, fd, m, EINVAL, NULL); return; }
	if (cp->next_spi < lo || cp->next_spi > hi) cp->next_spi = lo;
	for (uint32_t tries = 0, span = hi - lo + 1; tries < span; tries++) {
		struct r2dp_sa k = *rq;
		uint32_t cand = cp->next_spi;
		cp->next_spi = cand >= hi ? lo : cand + 1;
		k.spi = htonl(cand);
		if (sa_find(cp, &k)) continue;
		if (!(e = sa_alloc(cp))) { reply_sa(cp, fd, m, ENOBUFS, NULL); return; }
		memset(e, 0, sizeof(*e));
		e->used = e->larval = 1;
		e->sa = *rq; e->sa.spi = htonl(cand);
		reply_sa(cp, fd, m, 0, e);
		return;
	}
	reply_sa(cp, fd, m, ENOSPC, NULL);
}

static int sa_commit(struct r2dp_cp *cp, struct sa_ent *e, const struct r2dp_msg *m, int was_new)
{
	struct sa_ent backup = *e;
	int r = 0;

	sa_store(e, m);
	if (e->larval || !e->added_mono) {            /* lifetimes run from the first install, not from refreshes */
		e->added_mono = mono_s(); e->added_wall = (uint64_t)time(NULL); e->soft_sent = 0;
	}
	e->larval = 0;
	if (cp->h.sa_set)
		r = cp->h.sa_set(cp->h.ctx, &e->sa, e->enc, e->auth);
	if (r < 0) {              /* dataplane refused: roll back */
		if (was_new) memset(e, 0, sizeof(*e)); else *e = backup;
		return -r;
	}
	return 0;
}

static void do_sa(struct r2dp_cp *cp, int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sa *rq = r2dp_msg_sa(m);
	struct sa_ent *e = sa_find(cp, rq);
	int r;

	switch (m->h.type) {
	case R2DP_SA_ADD: {
		int was_new = 0;
		log_sa(cp, "SA_ADD", rq);
		if (e && !e->larval) { reply_sa(cp, fd, m, EEXIST, NULL); return; }
		if (!e) { if (!(e = sa_alloc(cp))) { reply_sa(cp, fd, m, ENOBUFS, NULL); return; }
		          memset(e, 0, sizeof(*e)); e->used = 1; was_new = 1; }
		if ((r = sa_commit(cp, e, m, was_new))) { reply_sa(cp, fd, m, r, NULL); return; }
		reply_sa(cp, fd, m, 0, e); return; }
	case R2DP_SA_UPDATE:
		log_sa(cp, "SA_UPDATE", rq);
		if (!e) { reply_sa(cp, fd, m, ENOENT, NULL); return; }
		if ((r = sa_commit(cp, e, m, 0))) { reply_sa(cp, fd, m, r, NULL); return; }
		reply_sa(cp, fd, m, 0, e); return;
	case R2DP_SA_DEL:
		log_sa(cp, "SA_DEL", rq);
		if (!e) { reply_sa(cp, fd, m, ENOENT, NULL); return; }
		if (!e->larval && cp->h.sa_del) cp->h.sa_del(cp->h.ctx, &e->sa);
		reply_sa(cp, fd, m, 0, e); e->used = 0; return;
	case R2DP_SA_GET:
		log_sa(cp, "SA_GET", rq);
		if (!e || e->larval) { reply_sa(cp, fd, m, ENOENT, NULL); return; }
		reply_sa(cp, fd, m, 0, e); return;
	}
}

static void do_sp(struct r2dp_cp *cp, int fd, const struct r2dp_msg *m)
{
	const struct r2dp_sp *rq = r2dp_msg_sp(m);
	struct sp_ent *e;
	struct r2dp_sp out;

	switch (m->h.type) {
	case R2DP_SP_ADD:
		LOG(cp, "SP_ADD dir=%u proto=%u pref=%u/%u action=%u mode=%u protos=0x%x reqid=%u upd=%u",
		    rq->dir, rq->ul_proto, rq->pref_src, rq->pref_dst, rq->action,
		    rq->mode, rq->protos, rq->reqid, !!(rq->flags & R2DP_SPF_UPDATE));
		e = sp_find(cp, rq, 1);
		if (e && !(rq->flags & R2DP_SPF_UPDATE)) { reply_sp(fd, m, EEXIST, rq, 0); return; }
		if (!e) {
			for (int i = 0; i < MAXSP && !e; i++) if (!cp->spd[i].used) e = &cp->spd[i];
			if (!e) { reply_sp(fd, m, ENOBUFS, rq, 0); return; }
			out = *rq; out.slid = rq->slid ? rq->slid : cp->next_slid++;
			out.flags &= ~R2DP_SPF_UPDATE;
			if (cp->h.sp_set) {
				int r = cp->h.sp_set(cp->h.ctx, &out);
				if (r < 0) { reply_sp(fd, m, -r, rq, 0); return; }
			}
			e->used = 1;
		} else {
			out = *rq; out.slid = e->sp.slid;
			out.flags &= ~R2DP_SPF_UPDATE;
			if (cp->h.sp_set) {
				int r = cp->h.sp_set(cp->h.ctx, &out);
				if (r < 0) { reply_sp(fd, m, -r, rq, 0); return; }
			}
		}
		e->sp = out;
		reply_sp(fd, m, 0, &out, 0); return;
	case R2DP_SP_DEL:
		LOG(cp, "SP_DEL slid=%u", rq->slid);
		e = rq->slid ? sp_find(cp, rq, 0) : sp_find(cp, rq, 1);
		if (!e) { reply_sp(fd, m, ENOENT, rq, 0); return; }
		out = e->sp; e->used = 0;
		if (cp->h.sp_del) cp->h.sp_del(cp->h.ctx, &out);
		reply_sp(fd, m, 0, &out, 0); return;
	case R2DP_SP_GET:
		LOG(cp, "SP_GET slid=%u", rq->slid);
		e = sp_find(cp, rq, 0);
		if (!e) { reply_sp(fd, m, ENOENT, rq, 0); return; }
		reply_sp(fd, m, 0, &e->sp, 0); return;
	case R2DP_SP_DUMP: {
		int last = -1;
		LOG(cp, "SP_DUMP");
		for (int i = 0; i < MAXSP; i++) if (cp->spd[i].used) last = i;
		if (last < 0) { reply_sp(fd, m, ENOENT, rq, 0); return; }
		for (int i = 0; i <= last; i++)
			if (cp->spd[i].used) {
				int more = 0;
				for (int j = i + 1; j <= last; j++) if (cp->spd[j].used) { more = 1; break; }
				reply_sp(fd, m, 0, &cp->spd[i].sp, more ? R2DP_HF_MORE : 0);
			}
		return; }
	}
}

void r2dp_cp_handle(struct r2dp_cp *cp, int fd, const struct r2dp_msg *m)
{
	switch (m->h.type) {
	case R2DP_HELLO:  do_hello(cp, fd, m); break;
	case R2DP_GETSPI: do_getspi(cp, fd, m); break;
	case R2DP_SA_ADD: case R2DP_SA_UPDATE: case R2DP_SA_DEL: case R2DP_SA_GET:
		do_sa(cp, fd, m); break;
	case R2DP_SP_ADD: case R2DP_SP_DEL: case R2DP_SP_GET: case R2DP_SP_DUMP:
		do_sp(cp, fd, m); break;
	default: /* HELLO_ACK/EXPIRE/ACQUIRE are forwarder->client only:
	          * refuse, echoing the (already validated) request body */
		r2dp_send(fd, m->h.type, m->h.seq, EPROTO, m->h.flags | R2DP_HF_NOKEYS,
		          m->body, m->h.len - sizeof(m->h), NULL, 0);
	}
}

void r2dp_cp_client_gone(struct r2dp_cp *cp, int fd)
{
	for (unsigned i = 0; i < cp->ncli; i++)
		if (cp->cli[i].fd == fd) { cp->cli[i] = cp->cli[--cp->ncli]; return; }
}

int r2dp_cp_sa_expired(struct r2dp_cp *cp, const struct r2dp_sa *key, int kind,
                       const struct r2dp_sa_counters *ctr)
{
	struct sa_ent *e = sa_find(cp, key);
	struct r2dp_sa ev;
	int sent = 0;

	if (!e || e->larval) return -ENOENT;
	ev = e->sa;
	ev.expired = (uint8_t)kind;
	ev.cur_alloc = ctr ? ctr->alloc : 1;
	ev.cur_add = e->added_wall;
	ev.cur_use = ctr ? ctr->use : 0;
	ev.cur_bytes = ctr ? ctr->bytes : 0;
	log_sa(cp, kind == R2DP_EXPIRE_HARD ? "EXPIRE(hard)" : "EXPIRE(soft)", &ev);
	for (unsigned i = 0; i < cp->ncli; i++) {
		if (cp->cli[i].role == R2DP_ROLE_SPMD || cp->cli[i].role == R2DP_ROLE_CTL) continue;
		if (r2dp_send_nowait(cp->cli[i].fd, R2DP_EXPIRE, 0, 0, R2DP_HF_NOKEYS, &ev, sizeof(ev), NULL, 0) == 0) {
			sent++; cp->ev_sent++;
		} else {
			cp->ev_dropped++;
			LOG(cp, "EXPIRE not delivered to fd=%d (client stalled or gone)", cp->cli[i].fd);
		}
	}
	if (kind == R2DP_EXPIRE_HARD) memset(e, 0, sizeof(*e));
	return sent;
}

void r2dp_cp_tick(struct r2dp_cp *cp)
{
	uint64_t now = mono_s();
	if (!cp->o.sw_lifetimes) return;
	for (int i = 0; i < MAXSA; i++) {
		struct sa_ent *e = &cp->sad[i];
		uint64_t age;
		if (!e->used || e->larval) continue;
		age = now - e->added_mono;
		if (e->sa.lft_hard_time && age >= e->sa.lft_hard_time) {
			struct r2dp_sa key = e->sa;
			if (cp->h.sa_del) cp->h.sa_del(cp->h.ctx, &key);   /* stop using it first, then announce */
			r2dp_cp_sa_expired(cp, &key, R2DP_EXPIRE_HARD, NULL);
		} else if (e->sa.lft_soft_time && !e->soft_sent && age >= e->sa.lft_soft_time) {
			struct r2dp_sa key = e->sa;
			e->soft_sent = 1;
			r2dp_cp_sa_expired(cp, &key, R2DP_EXPIRE_SOFT, NULL);
		}
	}
}

int r2dp_cp_dispatch(struct r2dp_cp *cp, int fd, const struct r2dp_msg *m, size_t n)
{
	int r = r2dp_validate(m, n);
	if (r == 0) { r2dp_cp_handle(cp, fd, m); return 0; }
	if (r == -ENOSYS) {
		r2dp_send(fd, m->h.type, m->h.seq, ENOSYS, R2DP_HF_NOKEYS, NULL, 0, NULL, 0);
		return 0;
	}
	return r;
}

int r2dp_cp_foreach_sa(struct r2dp_cp *cp,
    void (*fn)(void *, const struct r2dp_sa *, const uint8_t *, const uint8_t *), void *arg)
{
	int n = 0;
	for (int i = 0; i < MAXSA; i++)
		if (cp->sad[i].used && !cp->sad[i].larval) {
			fn(arg, &cp->sad[i].sa, cp->sad[i].enc, cp->sad[i].auth); n++;
		}
	return n;
}

/* --------------------------------------------------------- server socket */
struct r2dp_srv { int lfd, ncli, cli[MAXCLI]; };

struct r2dp_srv *r2dp_srv_new(const char *path)
{
	struct r2dp_srv *s = calloc(1, sizeof(*s));
	int fd;
	if (!s) return NULL;
	if ((fd = r2dp_listen(path, 8)) < 0) { free(s); errno = -fd; return NULL; }
	s->lfd = fd;
	return s;
}
int r2dp_srv_fd(const struct r2dp_srv *s) { return s->lfd; }

int r2dp_srv_poll(struct r2dp_srv *s, struct r2dp_cp *cp, int timeout_ms)
{
	struct pollfd pf[MAXCLI + 1];
	int n = 0, handled = 0;

	pf[n].fd = s->lfd; pf[n++].events = POLLIN;
	for (int i = 0; i < s->ncli; i++) { pf[n].fd = s->cli[i]; pf[n++].events = POLLIN; }
	if (poll(pf, n, timeout_ms) < 0) return errno == EINTR ? 0 : -errno;
	if (pf[0].revents & POLLIN) {
		int fd = r2dp_accept(s->lfd);
		if (fd >= 0 && s->ncli < MAXCLI) s->cli[s->ncli++] = fd;
		else if (fd >= 0) close(fd);
	}
	for (int i = 0; i < n - 1; i++) {
		struct r2dp_msg m;
		int r;
		if (!(pf[i + 1].revents & (POLLIN | POLLHUP | POLLERR))) continue;
		r = r2dp_recv(pf[i + 1].fd, &m);
		if (r == 0) { r2dp_cp_handle(cp, pf[i + 1].fd, &m); handled++; continue; }
		if (r == -ENOSYS) {
			r2dp_send(pf[i + 1].fd, m.h.type, m.h.seq, ENOSYS, R2DP_HF_NOKEYS, NULL, 0, NULL, 0);
			continue;
		}
		LOG(cp, "drop client fd=%d: %s", pf[i + 1].fd, strerror(-r));
		r2dp_cp_client_gone(cp, pf[i + 1].fd);
		close(pf[i + 1].fd);
		for (int j = 0; j < s->ncli; j++)
			if (s->cli[j] == pf[i + 1].fd) { s->cli[j] = s->cli[--s->ncli]; break; }
	}
	return handled;
}

void r2dp_srv_free(struct r2dp_srv *s)
{
	if (!s) return;
	for (int i = 0; i < s->ncli; i++) close(s->cli[i]);
	close(s->lfd); free(s);
}

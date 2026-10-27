/*
 * fwd/dp_xfrm.c -- Linux kernel XFRM data plane behind the fwd_dp vtable.
 *
 * `r2dp-fwd --dp kernel` serves the same r2dp socket, but programs the
 * kernel's SAD/SPD over NETLINK_XFRM instead of running DPDK, so the
 * kernel can act as a conformance reference for the DPDK forwarder (same
 * r2dp requests in, same observable traffic out) and as a fallback data
 * plane where DPDK is unavailable.  The design follows the upstream
 * prototype's kfwd.
 *
 * Contract (shared with dp_dpdk.c):
 *  - every request is applied to the kernel BEFORE ctl.c commits it, and
 *    the kernel's errno is what the client sees -- one netlink transaction
 *    per request, so nothing is ever half-applied; a policy upsert that
 *    changes the selector installs the new policy first and only then
 *    removes the old one (rolling the new one back if that fails);
 *  - SA direction comes from the v2 r2dp_sa.dir (via FWD_DP_SA_INBOUND):
 *    inbound SAs always carry an XFRMA_REPLAY_ESN_VAL bitmap replay state,
 *    so windows larger than the legacy 32-bit field work (wsize 0 -> 64);
 *    the ESN flag is set only when the SA negotiated ESN;
 *  - lifetimes stay with ctl.c (it sends EXPIRE); the kernel gets none, so
 *    it never deletes an SA behind ctl's back.  sa_bytes reads curlft;
 *  - the advertised transforms come from a startup probe (install and
 *    delete a throwaway state per algorithm), not a static list;
 *  - with --dp-cleanup everything this process installed is removed on
 *    exit (only ours: no flush).
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>

#include "dp.h"
#include "dp_sel.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif
#ifndef NLM_F_ACK_TLVS
#define NLM_F_ACK_TLVS 0x200
#endif
#ifndef NLM_F_CAPPED
#define NLM_F_CAPPED 0x100
#endif
#ifndef NLMSGERR_ATTR_MSG
#define NLMSGERR_ATTR_MSG 1
#endif
#define UDP_ENCAP_ESPINUDP_ 2
#define KX_MAXSA 1024
#define KX_MAXSP 1024
#define KX_PRIO_BASE 10000u

struct kx_sa { int used; struct r2dp_sa sa; };
struct kx_sp { int used; struct r2dp_sp sp; };

struct kx {
	int fd, verbose, cleanup;
	uint32_t seq;
	struct kx_sa sa[KX_MAXSA];   /* what we installed (cleanup, upsert) */
	struct kx_sp sp[KX_MAXSP];
	uint32_t enc[8], integ[8];   /* probed capabilities */
};

/* ------------------------------------------------------ netlink plumbing */
struct nlb { uint8_t b[4096]; size_t len; };

static void
nlb_init(struct nlb *n, uint16_t type, uint16_t flags, const void *body,
    size_t blen)
{
	struct nlmsghdr *h = (struct nlmsghdr *)n->b;

	memset(n->b, 0, NLMSG_ALIGN(NLMSG_LENGTH(blen)));
	h->nlmsg_type = type;
	h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	memcpy(NLMSG_DATA(h), body, blen);
	n->len = NLMSG_ALIGN(NLMSG_LENGTH(blen));
}

static int
nlb_attr(struct nlb *n, uint16_t type, const void *d, size_t l)
{
	struct nlattr *a;
	size_t need = NLA_ALIGN(NLA_HDRLEN + l);

	if (n->len + need > sizeof(n->b))
		return -E2BIG;
	a = (struct nlattr *)(n->b + n->len);
	memset(a, 0, need);
	a->nla_type = type;
	a->nla_len = (uint16_t)(NLA_HDRLEN + l);
	if (l)
		memcpy((uint8_t *)a + NLA_HDRLEN, d, l);
	n->len += need;
	return 0;
}

/* Send one request; wait for its ACK/ERROR (0 or the kernel's -errno).  If
 * `reply` is set, the first non-error message for this seq is copied there
 * (GET requests answer with data, then no ACK). */
static int
nl_xfer(struct kx *k, struct nlb *n, char *why, size_t whylen,
    void *reply, size_t rlen)
{
	struct nlmsghdr *h = (struct nlmsghdr *)n->b;
	struct sockaddr_nl kern = { .nl_family = AF_NETLINK };
	static uint8_t rbuf[16384];
	ssize_t r;

	if (k->fd < 0)
		return -EBADF;
	h->nlmsg_len = (uint32_t)n->len;
	h->nlmsg_seq = ++k->seq;
	if (why && whylen)
		why[0] = 0;
	if (sendto(k->fd, n->b, n->len, 0, (struct sockaddr *)&kern,
	    sizeof(kern)) < 0)
		return -errno;
	for (;;) {
		struct nlmsghdr *rh;
		r = recv(k->fd, rbuf, sizeof(rbuf), 0);
		if (r < 0)
			return errno == EAGAIN ? -ETIMEDOUT : -errno;
		for (rh = (struct nlmsghdr *)rbuf; NLMSG_OK(rh, (uint32_t)r);
		    rh = NLMSG_NEXT(rh, r)) {
			struct nlmsgerr *e;
			if (rh->nlmsg_seq != h->nlmsg_seq)
				continue;
			if (rh->nlmsg_type != NLMSG_ERROR) {
				if (reply) {
					size_t l = rh->nlmsg_len < rlen ?
					    rh->nlmsg_len : rlen;
					memcpy(reply, rh, l);
					return 0;
				}
				continue;
			}
			e = NLMSG_DATA(rh);
			if (e->error && why && whylen &&
			    (rh->nlmsg_flags & NLM_F_ACK_TLVS)) {
				size_t off = sizeof(struct nlmsgerr);
				uint8_t *p, *end = (uint8_t *)rh + rh->nlmsg_len;
				if (!(rh->nlmsg_flags & NLM_F_CAPPED))
					off += e->msg.nlmsg_len - sizeof(struct nlmsghdr);
				for (p = (uint8_t *)e + off; p + NLA_HDRLEN <= end;) {
					struct nlattr *a = (struct nlattr *)p;
					if (a->nla_len < NLA_HDRLEN)
						break;
					if ((a->nla_type & NLA_TYPE_MASK) ==
					    NLMSGERR_ATTR_MSG) {
						snprintf(why, whylen, "%s",
						    (char *)a + NLA_HDRLEN);
						break;
					}
					p += NLA_ALIGN(a->nla_len);
				}
			}
			return e->error;
		}
	}
}

/* ------------------------------------------------------ r2dp -> xfrm maps */
struct enc_map { uint8_t id; const char *name; uint16_t icv_bits; int aead;
	uint16_t keylen; };
static const struct enc_map enc_tab[] = {
	{ R2DP_ENCR_AES_GCM_8,  "rfc4106(gcm(aes))", 64,  1, 20 },
	{ R2DP_ENCR_AES_GCM_12, "rfc4106(gcm(aes))", 96,  1, 20 },
	{ R2DP_ENCR_AES_GCM_16, "rfc4106(gcm(aes))", 128, 1, 20 },
	/* CCM's salt is 3 bytes (RFC 4309): AES-128 key 16 + 3 */
	{ R2DP_ENCR_AES_CCM_8,  "rfc4309(ccm(aes))", 64,  1, 19 },
	{ R2DP_ENCR_AES_CCM_12, "rfc4309(ccm(aes))", 96,  1, 19 },
	{ R2DP_ENCR_AES_CCM_16, "rfc4309(ccm(aes))", 128, 1, 19 },
	{ R2DP_ENCR_CHACHA20_POLY1305, "rfc7539esp(chacha20,poly1305)", 128, 1, 36 },
	{ R2DP_ENCR_AES_CBC,    "cbc(aes)",          0,   0, 16 },
	{ R2DP_ENCR_AES_CTR,    "rfc3686(ctr(aes))", 0,   0, 20 },
	{ R2DP_ENCR_3DES,       "cbc(des3_ede)",     0,   0, 24 },
	{ R2DP_ENCR_NULL,       "ecb(cipher_null)",  0,   0, 0 },
};
struct integ_map { uint8_t id; const char *name; uint16_t trunc_bits;
	uint16_t keylen; };
static const struct integ_map integ_tab[] = {
	{ R2DP_INTEG_HMAC_MD5_96,       "hmac(md5)",    96,  16 },
	{ R2DP_INTEG_HMAC_SHA1_96,      "hmac(sha1)",   96,  20 },
	{ R2DP_INTEG_AES_XCBC_96,       "xcbc(aes)",    96,  16 },
	{ R2DP_INTEG_AES_CMAC_96,       "cmac(aes)",    96,  16 },
	{ R2DP_INTEG_HMAC_SHA2_256_128, "hmac(sha256)", 128, 32 },
	{ R2DP_INTEG_HMAC_SHA2_384_192, "hmac(sha384)", 192, 48 },
	{ R2DP_INTEG_HMAC_SHA2_512_256, "hmac(sha512)", 256, 64 },
};
#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

static const struct enc_map *
find_enc(uint8_t id)
{
	for (unsigned i = 0; i < NELEM(enc_tab); i++)
		if (enc_tab[i].id == id)
			return &enc_tab[i];
	return NULL;
}

static const struct integ_map *
find_integ(uint8_t id)
{
	for (unsigned i = 0; i < NELEM(integ_tab); i++)
		if (integ_tab[i].id == id)
			return &integ_tab[i];
	return NULL;
}

static int
fam_of(const struct r2dp_addr *a)
{
	return a->family == R2DP_AF_INET4 ? AF_INET :
	    a->family == R2DP_AF_INET6 ? AF_INET6 : 0;
}

static void
put_addr(xfrm_address_t *x, const struct r2dp_addr *a)
{
	memset(x, 0, sizeof(*x));
	if (a->family == R2DP_AF_INET4)
		memcpy(&x->a4, a->addr, 4);
	else if (a->family == R2DP_AF_INET6)
		memcpy(x->a6, a->addr, 16);
}

static void
lft_inf(struct xfrm_lifetime_cfg *l)
{
	memset(l, 0, sizeof(*l));
	l->soft_byte_limit = l->hard_byte_limit = XFRM_INF;
	l->soft_packet_limit = l->hard_packet_limit = XFRM_INF;
}

/* ---------------------------------------------------------------- states */
static int
build_sa(struct nlb *n, uint16_t type, const struct r2dp_sa *sa,
    const uint8_t *enc, const uint8_t *auth, int inbound)
{
	struct xfrm_usersa_info x;
	const struct enc_map *em = NULL;
	const struct integ_map *im = NULL;
	uint8_t ab[sizeof(struct xfrm_algo_aead) + 2 * R2DP_MAX_KEY];
	int fam = fam_of(&sa->src), esn = (sa->saflags & R2DP_SAF_ESN) != 0, r;

	if (!fam || fam != fam_of(&sa->dst))
		return -EAFNOSUPPORT;
	if (sa->proto != R2DP_PROTO_ESP && sa->proto != R2DP_PROTO_AH)
		return -EOPNOTSUPP;
	if (sa->mode != R2DP_MODE_TUNNEL && sa->mode != R2DP_MODE_TRANSPORT)
		return -EINVAL;
	if (sa->enc && !(em = find_enc(sa->enc)))
		return -EOPNOTSUPP;
	if (sa->integ && !(im = find_integ(sa->integ)))
		return -EOPNOTSUPP;
	if (sa->proto == R2DP_PROTO_ESP && !em)
		return -EINVAL;
	if (sa->proto == R2DP_PROTO_AH && (em || !im))
		return -EINVAL;
	if (em && em->aead && im)
		return -EINVAL;          /* AEAD carries its own integrity */
	if (em && !em->aead && em->id != R2DP_ENCR_NULL && !im)
		return -EINVAL;
	if (sa->enckeylen > R2DP_MAX_KEY || sa->authkeylen > R2DP_MAX_KEY)
		return -EINVAL;

	memset(&x, 0, sizeof(x));
	x.sel.family = (uint16_t)fam;   /* wildcard selector, as iproute2 */
	put_addr(&x.id.daddr, &sa->dst);
	x.id.spi = sa->spi;
	x.id.proto = sa->proto;
	put_addr(&x.saddr, &sa->src);
	lft_inf(&x.lft);                /* lifetimes are enforced by ctl.c */
	x.reqid = sa->reqid;
	x.family = (uint16_t)fam;
	x.mode = sa->mode == R2DP_MODE_TUNNEL ? XFRM_MODE_TUNNEL :
	    XFRM_MODE_TRANSPORT;
	x.replay_window = 0;            /* the ESN_VAL attribute carries it */
	x.flags = esn ? XFRM_STATE_ESN : 0;
	nlb_init(n, type, 0, &x, sizeof(x));

	if (em && em->aead) {
		struct xfrm_algo_aead *a = (struct xfrm_algo_aead *)ab;
		memset(a, 0, sizeof(*a));
		snprintf(a->alg_name, sizeof(a->alg_name), "%s", em->name);
		a->alg_key_len = (unsigned)sa->enckeylen * 8;
		a->alg_icv_len = em->icv_bits;
		memcpy(a->alg_key, enc, sa->enckeylen);
		if ((r = nlb_attr(n, XFRMA_ALG_AEAD, a, sizeof(*a) + sa->enckeylen)))
			return r;
	} else if (em) {
		struct xfrm_algo *a = (struct xfrm_algo *)ab;
		memset(a, 0, sizeof(*a));
		snprintf(a->alg_name, sizeof(a->alg_name), "%s", em->name);
		a->alg_key_len = (unsigned)sa->enckeylen * 8;
		memcpy(a->alg_key, enc, sa->enckeylen);
		if ((r = nlb_attr(n, XFRMA_ALG_CRYPT, a, sizeof(*a) + sa->enckeylen)))
			return r;
	}
	if (im) {
		struct xfrm_algo_auth *a = (struct xfrm_algo_auth *)ab;
		memset(a, 0, sizeof(*a));
		snprintf(a->alg_name, sizeof(a->alg_name), "%s", im->name);
		a->alg_key_len = (unsigned)sa->authkeylen * 8;
		a->alg_trunc_len = im->trunc_bits;
		memcpy(a->alg_key, auth, sa->authkeylen);
		if ((r = nlb_attr(n, XFRMA_ALG_AUTH_TRUNC, a,
		    sizeof(*a) + sa->authkeylen)))
			return r;
	}
	if (sa->natt_type == R2DP_NATT_ESPINUDP) {
		struct xfrm_encap_tmpl e;
		memset(&e, 0, sizeof(e));
		e.encap_type = UDP_ENCAP_ESPINUDP_;
		e.encap_sport = sa->natt_sport;
		e.encap_dport = sa->natt_dport;
		if ((r = nlb_attr(n, XFRMA_ENCAP, &e, sizeof(e))))
			return r;
	}
	/* Replay state: always the bitmap (ESN_VAL) form on inbound SAs, so a
	 * window above the legacy u8/32-bit limit works; outbound SAs only
	 * need it to carry the 64-bit counter under ESN. */
	if (inbound || esn) {
		uint8_t eb[sizeof(struct xfrm_replay_state_esn) + 4 * 8];
		struct xfrm_replay_state_esn *e = (struct xfrm_replay_state_esn *)eb;
		unsigned win = inbound ? (sa->wsize ? sa->wsize : 64) : 0;
		unsigned words = (win + 31) / 32;
		memset(eb, 0, sizeof(eb));
		e->bmp_len = words;
		e->replay_window = win;
		if ((r = nlb_attr(n, XFRMA_REPLAY_ESN_VAL, e,
		    sizeof(*e) + 4 * words)))
			return r;
	}
	return 0;
}

static struct kx_sa *
kx_sa_find(struct kx *k, const struct r2dp_sa *sa)
{
	for (int i = 0; i < KX_MAXSA; i++)
		if (k->sa[i].used && k->sa[i].sa.spi == sa->spi &&
		    k->sa[i].sa.proto == sa->proto &&
		    !memcmp(k->sa[i].sa.dst.addr, sa->dst.addr, 16))
			return &k->sa[i];
	return NULL;
}

static int
sa_del_kernel(struct kx *k, const struct r2dp_sa *sa)
{
	struct xfrm_usersa_id id;
	struct nlb n;

	if (!fam_of(&sa->dst))
		return -EAFNOSUPPORT;
	memset(&id, 0, sizeof(id));
	put_addr(&id.daddr, &sa->dst);
	id.spi = sa->spi;
	id.family = (uint16_t)fam_of(&sa->dst);
	id.proto = sa->proto;
	nlb_init(&n, XFRM_MSG_DELSA, 0, &id, sizeof(id));
	return nl_xfer(k, &n, NULL, 0, NULL, 0);
}

static int
kx_sa_add(struct fwd_dp *dp, int add, const struct r2dp_sa *sa,
    const void *blob, size_t blen)
{
	struct kx *k = dp->priv;
	struct kx_sa *e = kx_sa_find(k, sa);
	const uint8_t *key = blob;
	char why[160] = "";
	struct nlb n;
	int r;

	if (!(add & 1)) {
		r = sa_del_kernel(k, sa);
		if (r == -ESRCH || r == -ENOENT)
			r = 0;                       /* already gone */
		if (!r && e)
			e->used = 0;
		if (k->verbose)
			fprintf(stderr, "r2dp-fwd[xfrm]: DELSA spi=0x%08x -> %s\n",
			    ntohl(sa->spi), r ? strerror(-r) : "ok");
		return r;
	}
	if (!key || blen != (size_t)sa->enckeylen + sa->authkeylen)
		return -EINVAL;
	/* NEWSA, or UPDSA (one atomic replace) for an SA we already hold */
	r = build_sa(&n, e ? XFRM_MSG_UPDSA : XFRM_MSG_NEWSA, sa, key,
	    key + sa->enckeylen, (add & FWD_DP_SA_INBOUND) != 0);
	if (!r)
		r = nl_xfer(k, &n, why, sizeof(why), NULL, 0);
	if (k->verbose)
		fprintf(stderr, "r2dp-fwd[xfrm]: %s spi=0x%08x dir=%s -> %s%s%s\n",
		    e ? "UPDSA" : "NEWSA", ntohl(sa->spi),
		    (add & FWD_DP_SA_INBOUND) ? "in" : "out",
		    r ? strerror(-r) : "ok", why[0] ? ": " : "", why);
	if (r)
		return r;
	if (!e) {
		for (int i = 0; i < KX_MAXSA && !e; i++)
			if (!k->sa[i].used)
				e = &k->sa[i];
		if (!e) {                    /* untracked would leak on cleanup */
			sa_del_kernel(k, sa);
			return -ENOBUFS;
		}
	}
	e->used = 1;
	e->sa = *sa;
	return 0;
}

static int64_t
kx_sa_bytes(struct fwd_dp *dp, uint32_t spi, uint32_t dip)
{
	struct kx *k = dp->priv;
	struct xfrm_usersa_id id;
	struct nlb n;
	static uint8_t rep[8192];
	struct nlmsghdr *h = (struct nlmsghdr *)rep;
	const struct xfrm_usersa_info *x;

	memset(&id, 0, sizeof(id));
	memcpy(&id.daddr.a4, &dip, 4);
	id.spi = spi;
	id.family = AF_INET;
	id.proto = IPPROTO_ESP;
	nlb_init(&n, XFRM_MSG_GETSA, 0, &id, sizeof(id));
	((struct nlmsghdr *)n.b)->nlmsg_flags &= ~NLM_F_ACK;
	if (nl_xfer(k, &n, NULL, 0, rep, sizeof(rep)) != 0 ||
	    h->nlmsg_type != XFRM_MSG_NEWSA ||
	    h->nlmsg_len < NLMSG_LENGTH(sizeof(*x)))
		return -1;
	x = NLMSG_DATA(h);
	return (int64_t)x->curlft.bytes;
}

/* -------------------------------------------------------------- policies */
static int
sp_fill_sel(struct xfrm_selector *s, const struct r2dp_sp *sp)
{
	int fs = fam_of(&sp->sel_src), fd = fam_of(&sp->sel_dst);
	int fam = fs ? fs : fd;

	if (!fam || (fs && fd && fs != fd))
		return -EINVAL;
	memset(s, 0, sizeof(*s));
	s->family = (uint16_t)fam;
	put_addr(&s->saddr, &sp->sel_src);
	put_addr(&s->daddr, &sp->sel_dst);
	s->prefixlen_s = sp->pref_src;
	s->prefixlen_d = sp->pref_dst;
	s->proto = sp->ul_proto == R2DP_PROTO_ANY ? 0 : sp->ul_proto;
	s->sport = sp->sel_src.port;
	s->sport_mask = sp->sel_src.port ? 0xffff : 0;
	s->dport = sp->sel_dst.port;
	s->dport_mask = sp->sel_dst.port ? 0xffff : 0;
	return 0;
}

static int
xdir(uint8_t d)
{
	return d == R2DP_DIR_IN ? XFRM_POLICY_IN : d == R2DP_DIR_OUT ?
	    XFRM_POLICY_OUT : d == R2DP_DIR_FWD ? XFRM_POLICY_FWD : -1;
}

static int
sp_set_kernel(struct kx *k, const struct r2dp_sp *sp)
{
	struct xfrm_userpolicy_info p;
	struct nlb n;
	char why[160] = "";
	int d = xdir(sp->dir), r;

	if (d < 0)
		return -EINVAL;
	memset(&p, 0, sizeof(p));
	if ((r = sp_fill_sel(&p.sel, sp)) < 0)
		return r;
	lft_inf(&p.lft);
	/* same "most specific wins" order as the DPDK SPD (lower = first) */
	p.priority = KX_PRIO_BASE - (uint32_t)r2dp_sel_score(sp);
	p.dir = (uint8_t)d;
	p.action = sp->action == R2DP_ACT_DISCARD ? XFRM_POLICY_BLOCK :
	    XFRM_POLICY_ALLOW;
	p.share = XFRM_SHARE_ANY;
	nlb_init(&n, XFRM_MSG_UPDPOLICY, 0, &p, sizeof(p));   /* upsert */
	if (sp->action == R2DP_ACT_PROTECT) {
		struct xfrm_user_tmpl t;
		int fam = fam_of(&sp->tun_src) ? fam_of(&sp->tun_src) : p.sel.family;
		if (sp->protos & ~(R2DP_SPP_ESP | R2DP_SPP_AH) ||
		    sp->protos == (R2DP_SPP_ESP | R2DP_SPP_AH))
			return -EOPNOTSUPP;         /* no bundles / IPcomp */
		if (sp->mode != R2DP_MODE_TUNNEL && sp->mode != R2DP_MODE_TRANSPORT)
			return -EINVAL;
		memset(&t, 0, sizeof(t));
		if (sp->mode == R2DP_MODE_TUNNEL) {
			if (!fam_of(&sp->tun_src) || !fam_of(&sp->tun_dst))
				return -EINVAL;
			put_addr(&t.saddr, &sp->tun_src);
			put_addr(&t.id.daddr, &sp->tun_dst);
		}
		t.id.proto = sp->protos == R2DP_SPP_AH ? IPPROTO_AH : IPPROTO_ESP;
		t.family = (uint16_t)fam;
		t.reqid = sp->reqid;
		t.mode = sp->mode == R2DP_MODE_TUNNEL ? XFRM_MODE_TUNNEL :
		    XFRM_MODE_TRANSPORT;
		t.aalgos = t.ealgos = t.calgos = ~0u;
		t.optional = sp->level == R2DP_LVL_USE;
		if ((r = nlb_attr(&n, XFRMA_TMPL, &t, sizeof(t))))
			return r;
	}
	r = nl_xfer(k, &n, why, sizeof(why), NULL, 0);
	if (k->verbose)
		fprintf(stderr, "r2dp-fwd[xfrm]: UPDPOLICY slid=%u dir=%u action=%u"
		    " -> %s%s%s\n", sp->slid, sp->dir, sp->action,
		    r ? strerror(-r) : "ok", why[0] ? ": " : "", why);
	return r;
}

static int
sp_del_kernel(struct kx *k, const struct r2dp_sp *sp)
{
	struct xfrm_userpolicy_id id;
	struct nlb n;
	int d = xdir(sp->dir), r;

	if (d < 0)
		return -EINVAL;
	memset(&id, 0, sizeof(id));
	if ((r = sp_fill_sel(&id.sel, sp)) < 0)
		return r;
	id.dir = (uint8_t)d;
	nlb_init(&n, XFRM_MSG_DELPOLICY, 0, &id, sizeof(id));
	r = nl_xfer(k, &n, NULL, 0, NULL, 0);
	if (r == -ENOENT)
		r = 0;
	return r;
}

/* same kernel key (dir + selector) => UPDPOLICY replaced it in place */
static int
same_kernel_key(const struct r2dp_sp *a, const struct r2dp_sp *b)
{
	struct xfrm_selector x, y;

	if (a->dir != b->dir || sp_fill_sel(&x, a) || sp_fill_sel(&y, b))
		return 0;
	return !memcmp(&x, &y, sizeof(x));
}

static struct kx_sp *
kx_sp_find(struct kx *k, uint32_t slid)
{
	for (int i = 0; i < KX_MAXSP; i++)
		if (k->sp[i].used && k->sp[i].sp.slid == slid)
			return &k->sp[i];
	return NULL;
}

static int
kx_sp_add(struct fwd_dp *dp, struct r2dp_sp *sp)
{
	struct kx *k = dp->priv;
	struct kx_sp *e = kx_sp_find(k, sp->slid);
	int r;

	if (!e)
		for (int i = 0; i < KX_MAXSP && !e; i++)
			if (!k->sp[i].used)
				e = &k->sp[i];
	if (!e)
		return -ENOBUFS;
	/* new policy first: on failure the old one is still in force */
	if ((r = sp_set_kernel(k, sp)))
		return r;
	if (e->used && !same_kernel_key(&e->sp, sp) &&
	    (r = sp_del_kernel(k, &e->sp))) {
		sp_del_kernel(k, sp);        /* roll back: keep the old only */
		return r;
	}
	e->used = 1;
	e->sp = *sp;
	return 0;
}

static int
kx_sp_del(struct fwd_dp *dp, const struct r2dp_sp *sp)
{
	struct kx *k = dp->priv;
	struct kx_sp *e = kx_sp_find(k, sp->slid);
	int r = sp_del_kernel(k, e ? &e->sp : sp);

	if (k->verbose)
		fprintf(stderr, "r2dp-fwd[xfrm]: DELPOLICY slid=%u -> %s\n",
		    sp->slid, r ? strerror(-r) : "ok");
	if (!r && e)
		e->used = 0;
	return r;
}

/* ---------------------------------------------------------------- caps */
static void
cap_set(uint32_t bm[8], unsigned id)
{
	bm[id >> 5] |= 1u << (id & 31);
}

/* Can the kernel hold a state with this transform?  (Crypto modules load
 * on first use, so /proc/crypto is not a reliable answer.)  Uses reserved
 * TEST-NET-1 addresses and an SPI no IKE daemon hands out. */
static int
probe_one(struct kx *k, uint8_t enc, uint8_t integ)
{
	const struct enc_map *em = find_enc(enc);
	const struct integ_map *im = find_integ(integ);
	struct r2dp_sa sa;
	uint8_t key[2 * R2DP_MAX_KEY];
	struct nlb n;
	int r;

	memset(&sa, 0, sizeof(sa));
	memset(key, 0x5a, sizeof(key));
	sa.src.family = sa.dst.family = R2DP_AF_INET4;
	sa.src.addr[0] = 192; sa.src.addr[2] = 2; sa.src.addr[3] = 254;
	sa.dst.addr[0] = 192; sa.dst.addr[2] = 2; sa.dst.addr[3] = 253;
	sa.spi = htonl(0xfffffff0u);
	sa.proto = R2DP_PROTO_ESP;
	sa.mode = R2DP_MODE_TUNNEL;
	sa.enc = enc;
	sa.integ = integ;
	sa.enckeylen = em ? em->keylen : 0;
	sa.authkeylen = im ? im->keylen : 0;
	if (build_sa(&n, XFRM_MSG_NEWSA, &sa, key, key + sa.enckeylen, 1))
		return 0;
	r = nl_xfer(k, &n, NULL, 0, NULL, 0);
	if (r == -EEXIST) {                 /* leftover from a crashed run */
		sa_del_kernel(k, &sa);
		r = nl_xfer(k, &n, NULL, 0, NULL, 0);
	}
	if (r == 0)
		sa_del_kernel(k, &sa);
	return r == 0;
}

static int
kx_probe(struct kx *k)
{
	int ok = 0;

	memset(k->enc, 0, sizeof(k->enc));
	memset(k->integ, 0, sizeof(k->integ));
	cap_set(k->integ, R2DP_INTEG_NONE);
	for (unsigned i = 0; i < NELEM(enc_tab); i++) {
		const struct enc_map *e = &enc_tab[i];
		if (probe_one(k, e->id, e->aead ? R2DP_INTEG_NONE :
		    R2DP_INTEG_HMAC_SHA1_96)) {
			cap_set(k->enc, e->id);
			ok++;
		}
	}
	for (unsigned i = 0; i < NELEM(integ_tab); i++)
		if (probe_one(k, R2DP_ENCR_AES_CBC, integ_tab[i].id)) {
			cap_set(k->integ, integ_tab[i].id);
			ok++;
		}
	return ok;
}

static void
kx_caps(struct fwd_dp *dp)
{
	struct kx *k = dp->priv;

	memcpy(dp->caps_bits_enc, k->enc, sizeof(k->enc));
	memcpy(dp->caps_bits_integ, k->integ, sizeof(k->integ));
}

static void
kx_stop(struct fwd_dp *dp)
{
	struct kx *k = dp->priv;
	int nsa = 0, nsp = 0;

	if (!k || k->fd < 0)
		return;
	if (k->cleanup) {
		for (int i = 0; i < KX_MAXSP; i++)
			if (k->sp[i].used && !sp_del_kernel(k, &k->sp[i].sp)) {
				k->sp[i].used = 0;
				nsp++;
			}
		for (int i = 0; i < KX_MAXSA; i++)
			if (k->sa[i].used) {
				int r = sa_del_kernel(k, &k->sa[i].sa);
				if (!r || r == -ESRCH) {
					k->sa[i].used = 0;
					nsa++;
				}
			}
		fprintf(stderr, "r2dp-fwd[xfrm]: cleanup removed %d SA(s), "
		    "%d SP(s)\n", nsa, nsp);
	}
	close(k->fd);
	k->fd = -1;
}

static struct fwd_dp_ops kx_ops = {
	.caps = kx_caps,
	.sa_add = kx_sa_add,
	.sp_add = kx_sp_add,
	.sp_del = kx_sp_del,
	.sa_bytes = kx_sa_bytes,
	.stop = kx_stop,
};

int
fwd_dp_xfrm_probe(struct fwd_dp *dp, int verbose, int cleanup)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct timeval tv = { .tv_sec = 3 };
	struct kx *k;
	int one = 1, n;

	k = calloc(1, sizeof(*k));
	if (!k)
		return -ENOMEM;
	k->verbose = verbose;
	k->cleanup = cleanup;
	k->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (k->fd < 0 || bind(k->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int e = -errno;
		if (k->fd >= 0)
			close(k->fd);
		free(k);
		return e;
	}
	setsockopt(k->fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));
	setsockopt(k->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	n = kx_probe(k);
	if (n == 0) {
		fprintf(stderr, "r2dp-fwd[xfrm]: the kernel accepts no ESP "
		    "transform (no esp4/xfrm crypto?)\n");
		close(k->fd);
		free(k);
		return -EOPNOTSUPP;
	}
	dp->priv = k;
	dp->ops = &kx_ops;
	kx_caps(dp);
	fprintf(stderr, "r2dp-fwd: kernel XFRM dataplane ready (%d transforms%s)\n",
	    n, cleanup ? ", cleanup on exit" : "");
	return 0;
}

/* Release the backend (tests).  Does not remove kernel state unless the
 * backend was opened with cleanup. */
void
fwd_dp_xfrm_free(struct fwd_dp *dp)
{
	if (dp->ops == &kx_ops) {
		kx_stop(dp);
		free(dp->priv);
		dp->priv = NULL;
		dp->ops = NULL;
	}
}

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include "xfrm.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif
#ifndef NLM_F_ACK_TLVS
#define NLM_F_ACK_TLVS 0x200
#endif
#ifndef NLMSGERR_ATTR_MSG
#define NLMSGERR_ATTR_MSG 1
#endif
#define UDP_ENCAP_ESPINUDP_ 2

static int g_fd = -1, g_verbose;
static uint32_t g_seq;

/* ------------------------------------------------------- netlink plumbing */
struct nlb { uint8_t b[4096]; size_t len; };

static void nlb_init(struct nlb *n, uint16_t type, uint16_t flags, const void *body, size_t blen)
{
	struct nlmsghdr *h = (struct nlmsghdr *)n->b;
	memset(n->b, 0, NLMSG_ALIGN(NLMSG_LENGTH(blen)));
	h->nlmsg_type = type;
	h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	memcpy(NLMSG_DATA(h), body, blen);
	n->len = NLMSG_ALIGN(NLMSG_LENGTH(blen));
}

static int nlb_attr(struct nlb *n, uint16_t type, const void *d, size_t l)
{
	struct nlattr *a;
	size_t need = NLA_ALIGN(NLA_HDRLEN + l);
	if (n->len + need > sizeof(n->b)) return -E2BIG;
	a = (struct nlattr *)(n->b + n->len);
	memset(a, 0, need);
	a->nla_type = type; a->nla_len = (uint16_t)(NLA_HDRLEN + l);
	if (l) memcpy((uint8_t *)a + NLA_HDRLEN, d, l);
	n->len += need;
	return 0;
}

/* Send one request and wait for its ACK/ERROR.  Returns 0 or -errno (the kernel's). */
static int nl_xfer(struct nlb *n, char *why, size_t whylen)
{
	struct nlmsghdr *h = (struct nlmsghdr *)n->b;
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	uint8_t rbuf[8192];
	ssize_t r;

	if (g_fd < 0) return -EBADF;
	h->nlmsg_len = (uint32_t)n->len;
	h->nlmsg_seq = ++g_seq;
	if (why && whylen) why[0] = 0;
	if (sendto(g_fd, n->b, n->len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) return -errno;
	for (;;) {
		struct nlmsghdr *rh;
		r = recv(g_fd, rbuf, sizeof(rbuf), 0);
		if (r < 0) return errno == EAGAIN ? -ETIMEDOUT : (errno == EINTR ? -EINTR : -errno);
		for (rh = (struct nlmsghdr *)rbuf; NLMSG_OK(rh, (uint32_t)r); rh = NLMSG_NEXT(rh, r)) {
			struct nlmsgerr *e;
			if (rh->nlmsg_seq != h->nlmsg_seq || rh->nlmsg_type != NLMSG_ERROR) continue;
			e = NLMSG_DATA(rh);
			if (e->error && why && whylen && (rh->nlmsg_flags & NLM_F_ACK_TLVS)) {
				size_t off = sizeof(struct nlmsgerr);
				uint8_t *p, *end = (uint8_t *)rh + rh->nlmsg_len;
				if (!(rh->nlmsg_flags & NLM_F_CAPPED)) off += e->msg.nlmsg_len - sizeof(struct nlmsghdr);
				for (p = (uint8_t *)e + off; p + NLA_HDRLEN <= end; ) {
					struct nlattr *a = (struct nlattr *)p;
					if (a->nla_len < NLA_HDRLEN) break;
					if ((a->nla_type & NLA_TYPE_MASK) == NLMSGERR_ATTR_MSG) {
						snprintf(why, whylen, "%s", (char *)a + NLA_HDRLEN);
						break;
					}
					p += NLA_ALIGN(a->nla_len);
				}
			}
			return e->error;                       /* 0 = ACK, else -errno */
		}
	}
}

int kx_open(int verbose)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct timeval tv = { .tv_sec = 3 };
	int one = 1;

	g_verbose = verbose;
	if ((g_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM)) < 0) return -errno;
	if (bind(g_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { int e = -errno; close(g_fd); g_fd = -1; return e; }
	setsockopt(g_fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));   /* best effort */
	setsockopt(g_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return 0;
}
void kx_close(void) { if (g_fd >= 0) close(g_fd); g_fd = -1; }

/* ------------------------------------------------------ r2dp -> xfrm maps */
struct enc_map { uint8_t id; const char *name; uint16_t icv_bits; int aead; };
static const struct enc_map enc_tab[] = {
	{ R2DP_ENCR_AES_GCM_8,  "rfc4106(gcm(aes))", 64,  1 },
	{ R2DP_ENCR_AES_GCM_12, "rfc4106(gcm(aes))", 96,  1 },
	{ R2DP_ENCR_AES_GCM_16, "rfc4106(gcm(aes))", 128, 1 },
	{ R2DP_ENCR_AES_CCM_8,  "rfc4309(ccm(aes))", 64,  1 },
	{ R2DP_ENCR_AES_CCM_12, "rfc4309(ccm(aes))", 96,  1 },
	{ R2DP_ENCR_AES_CCM_16, "rfc4309(ccm(aes))", 128, 1 },
	{ R2DP_ENCR_CHACHA20_POLY1305, "rfc7539esp(chacha20,poly1305)", 128, 1 },
	{ R2DP_ENCR_AES_CBC,    "cbc(aes)",          0,   0 },
	{ R2DP_ENCR_3DES,       "cbc(des3_ede)",     0,   0 },
	{ R2DP_ENCR_NULL,       "ecb(cipher_null)",  0,   0 },
};
struct integ_map { uint8_t id; const char *name; uint16_t trunc_bits; };
static const struct integ_map integ_tab[] = {
	{ R2DP_INTEG_HMAC_MD5_96,       "hmac(md5)",    96  },
	{ R2DP_INTEG_HMAC_SHA1_96,      "hmac(sha1)",   96  },
	{ R2DP_INTEG_AES_XCBC_96,       "xcbc(aes)",    96  },
	{ R2DP_INTEG_AES_CMAC_96,       "cmac(aes)",    96  },
	{ R2DP_INTEG_HMAC_SHA2_256_128, "hmac(sha256)", 128 },
	{ R2DP_INTEG_HMAC_SHA2_384_192, "hmac(sha384)", 192 },
	{ R2DP_INTEG_HMAC_SHA2_512_256, "hmac(sha512)", 256 },
};
static const struct enc_map *find_enc(uint8_t id)
{ for (unsigned i = 0; i < sizeof(enc_tab) / sizeof(enc_tab[0]); i++) if (enc_tab[i].id == id) return &enc_tab[i]; return NULL; }
static const struct integ_map *find_integ(uint8_t id)
{ for (unsigned i = 0; i < sizeof(integ_tab) / sizeof(integ_tab[0]); i++) if (integ_tab[i].id == id) return &integ_tab[i]; return NULL; }

static int fam_of(const struct r2dp_addr *a)
{ return a->family == R2DP_AF_INET4 ? AF_INET : a->family == R2DP_AF_INET6 ? AF_INET6 : 0; }

static void put_addr(xfrm_address_t *x, const struct r2dp_addr *a)
{
	memset(x, 0, sizeof(*x));
	if (a->family == R2DP_AF_INET4) memcpy(&x->a4, a->addr, 4);
	else if (a->family == R2DP_AF_INET6) memcpy(x->a6, a->addr, 16);
}

static void lft_inf(struct xfrm_lifetime_cfg *l)
{
	memset(l, 0, sizeof(*l));
	l->soft_byte_limit = l->hard_byte_limit = XFRM_INF;
	l->soft_packet_limit = l->hard_packet_limit = XFRM_INF;
}

/* ---------------------------------------------------------------- states */
static int build_sa(struct nlb *n, uint16_t type, uint16_t flags, const struct r2dp_sa *sa,
                    const uint8_t *enc, const uint8_t *auth)
{
	struct xfrm_usersa_info x;
	const struct enc_map *em = NULL;
	const struct integ_map *im = NULL;
	uint8_t ab[sizeof(struct xfrm_algo_aead) + 2 * R2DP_MAX_KEY];
	int fam = fam_of(&sa->src), r;

	if (!fam || fam != fam_of(&sa->dst)) return -EAFNOSUPPORT;
	if (sa->proto != R2DP_PROTO_ESP && sa->proto != R2DP_PROTO_AH) return -EOPNOTSUPP;
	if (sa->mode != R2DP_MODE_TUNNEL && sa->mode != R2DP_MODE_TRANSPORT) return -EINVAL;
	if (sa->enc && !(em = find_enc(sa->enc))) return -EOPNOTSUPP;
	if (sa->integ && !(im = find_integ(sa->integ))) return -EOPNOTSUPP;
	if (sa->proto == R2DP_PROTO_ESP && !em) return -EINVAL;
	if (sa->proto == R2DP_PROTO_AH && (em || !im)) return -EINVAL;
	if (em && em->aead && im) return -EINVAL;          /* AEAD carries its own integrity */
	if (em && !em->aead && em->id != R2DP_ENCR_NULL && !im) return -EINVAL;

	memset(&x, 0, sizeof(x));
	x.sel.family = (uint16_t)fam;                       /* wildcard selector, as iproute2 does */
	put_addr(&x.id.daddr, &sa->dst); x.id.spi = sa->spi; x.id.proto = sa->proto;
	put_addr(&x.saddr, &sa->src);
	lft_inf(&x.lft);
	if (sa->lft_hard_bytes) x.lft.hard_byte_limit = sa->lft_hard_bytes;
	if (sa->lft_soft_bytes) x.lft.soft_byte_limit = sa->lft_soft_bytes;
	x.lft.hard_add_expires_seconds = sa->lft_hard_time;
	x.lft.soft_add_expires_seconds = sa->lft_soft_time;
	x.reqid = sa->reqid;
	x.family = (uint16_t)fam;
	x.mode = sa->mode == R2DP_MODE_TUNNEL ? XFRM_MODE_TUNNEL : XFRM_MODE_TRANSPORT;
	x.replay_window = (sa->saflags & R2DP_SAF_ESN) ? 0 : sa->wsize;
	x.flags = (sa->saflags & R2DP_SAF_ESN) ? XFRM_STATE_ESN : 0;
	nlb_init(n, type, flags, &x, sizeof(x));

	if (em && em->aead) {
		struct xfrm_algo_aead *a = (struct xfrm_algo_aead *)ab;
		memset(a, 0, sizeof(*a));
		snprintf(a->alg_name, sizeof(a->alg_name), "%s", em->name);
		a->alg_key_len = (unsigned)sa->enckeylen * 8; a->alg_icv_len = em->icv_bits;
		memcpy(a->alg_key, enc, sa->enckeylen);
		if ((r = nlb_attr(n, XFRMA_ALG_AEAD, a, sizeof(*a) + sa->enckeylen))) return r;
	} else if (em) {
		struct xfrm_algo *a = (struct xfrm_algo *)ab;
		memset(a, 0, sizeof(*a));
		snprintf(a->alg_name, sizeof(a->alg_name), "%s", em->name);
		a->alg_key_len = (unsigned)sa->enckeylen * 8;
		memcpy(a->alg_key, enc, sa->enckeylen);
		if ((r = nlb_attr(n, XFRMA_ALG_CRYPT, a, sizeof(*a) + sa->enckeylen))) return r;
	}
	if (im) {
		struct xfrm_algo_auth *a = (struct xfrm_algo_auth *)ab;
		memset(a, 0, sizeof(*a));
		snprintf(a->alg_name, sizeof(a->alg_name), "%s", im->name);
		a->alg_key_len = (unsigned)sa->authkeylen * 8; a->alg_trunc_len = im->trunc_bits;
		memcpy(a->alg_key, auth, sa->authkeylen);
		if ((r = nlb_attr(n, XFRMA_ALG_AUTH_TRUNC, a, sizeof(*a) + sa->authkeylen))) return r;
	}
	if (sa->natt_type == R2DP_NATT_ESPINUDP) {
		struct xfrm_encap_tmpl e;
		memset(&e, 0, sizeof(e));
		e.encap_type = UDP_ENCAP_ESPINUDP_;
		e.encap_sport = sa->natt_sport; e.encap_dport = sa->natt_dport;
		if ((r = nlb_attr(n, XFRMA_ENCAP, &e, sizeof(e)))) return r;
	}
	if (sa->saflags & R2DP_SAF_ESN) {
		uint8_t eb[sizeof(struct xfrm_replay_state_esn) + 4 * 64];
		struct xfrm_replay_state_esn *e = (struct xfrm_replay_state_esn *)eb;
		unsigned win = sa->wsize ? sa->wsize : 64, words = (win + 31) / 32;
		if (words > 64) return -EINVAL;
		memset(eb, 0, sizeof(eb));
		e->bmp_len = words; e->replay_window = win;
		if ((r = nlb_attr(n, XFRMA_REPLAY_ESN_VAL, e, sizeof(*e) + 4 * words))) return r;
	}
	return 0;
}

static int sa_install(const struct r2dp_sa *sa, const uint8_t *enc, const uint8_t *auth)
{
	struct nlb n;
	char why[160];
	int r;

	if ((r = build_sa(&n, XFRM_MSG_NEWSA, 0, sa, enc, auth))) return r;
	r = nl_xfer(&n, why, sizeof(why));
	if (r == -EEXIST) {                                   /* rekey/refresh of a known SA */
		if ((r = build_sa(&n, XFRM_MSG_UPDSA, 0, sa, enc, auth))) return r;
		r = nl_xfer(&n, why, sizeof(why));
	}
	if (g_verbose)
		fprintf(stderr, "kfwd: NEWSA spi=0x%08x -> %s%s%s\n", ntohl(sa->spi), r ? strerror(-r) : "ok",
		        why[0] ? ": " : "", why);
	return r;
}

static void sa_remove(const struct r2dp_sa *sa)
{
	struct xfrm_usersa_id id;
	struct nlb n;
	int r;

	if (!fam_of(&sa->dst)) return;
	memset(&id, 0, sizeof(id));
	put_addr(&id.daddr, &sa->dst); id.spi = sa->spi; id.family = (uint16_t)fam_of(&sa->dst); id.proto = sa->proto;
	nlb_init(&n, XFRM_MSG_DELSA, 0, &id, sizeof(id));
	r = nl_xfer(&n, NULL, 0);
	if (g_verbose) fprintf(stderr, "kfwd: DELSA spi=0x%08x -> %s\n", ntohl(sa->spi), r ? strerror(-r) : "ok");
}

/* -------------------------------------------------------------- policies */
static int sp_fill_sel(struct xfrm_selector *s, const struct r2dp_sp *sp)
{
	int fs = fam_of(&sp->sel_src), fd = fam_of(&sp->sel_dst), fam = fs ? fs : fd;
	if (!fam) return 1;                                   /* family-less wildcard: not expressible */
	if ((fs && fd && fs != fd)) return -EINVAL;
	memset(s, 0, sizeof(*s));
	s->family = (uint16_t)fam;
	put_addr(&s->saddr, &sp->sel_src); put_addr(&s->daddr, &sp->sel_dst);
	s->prefixlen_s = sp->pref_src; s->prefixlen_d = sp->pref_dst;
	s->proto = sp->ul_proto == R2DP_PROTO_ANY ? 0 : sp->ul_proto;
	s->sport = sp->sel_src.port; s->sport_mask = sp->sel_src.port ? 0xffff : 0;
	s->dport = sp->sel_dst.port; s->dport_mask = sp->sel_dst.port ? 0xffff : 0;
	return 0;
}

static int xdir(uint8_t d)
{ return d == R2DP_DIR_IN ? XFRM_POLICY_IN : d == R2DP_DIR_OUT ? XFRM_POLICY_OUT : d == R2DP_DIR_FWD ? XFRM_POLICY_FWD : -1; }

/* r2dp specificity (higher = more specific) -> kernel priority (lower = wins). */
static uint32_t xprio(const struct r2dp_sp *sp)
{
	int spec = sp->pref_src + sp->pref_dst + (sp->ul_proto != R2DP_PROTO_ANY ? 100 : 0) +
	           (sp->sel_src.port ? 50 : 0) + (sp->sel_dst.port ? 50 : 0);
	return (uint32_t)(10000 - spec);
}

static int sp_install(const struct r2dp_sp *sp)
{
	struct xfrm_userpolicy_info p;
	struct nlb n;
	char why[160];
	int d = xdir(sp->dir), r;

	if (d < 0) return -EINVAL;
	memset(&p, 0, sizeof(p));
	if ((r = sp_fill_sel(&p.sel, sp)) > 0) {
		if (g_verbose) fprintf(stderr, "kfwd: SP slid=%u has no address family; not programmed\n", sp->slid);
		return 0;
	} else if (r < 0) return r;
	lft_inf(&p.lft);
	p.priority = xprio(sp);
	p.dir = (uint8_t)d;
	p.action = sp->action == R2DP_ACT_DISCARD ? XFRM_POLICY_BLOCK : XFRM_POLICY_ALLOW;
	p.share = XFRM_SHARE_ANY;
	nlb_init(&n, XFRM_MSG_UPDPOLICY, 0, &p, sizeof(p));     /* upsert: UPDPOLICY inserts or replaces */

	if (sp->action == R2DP_ACT_PROTECT) {
		struct xfrm_user_tmpl t;
		int fam = fam_of(&sp->tun_src) ? fam_of(&sp->tun_src) : p.sel.family;
		if (sp->protos != R2DP_SPP_ESP && sp->protos != R2DP_SPP_AH) return -EOPNOTSUPP;   /* no bundles */
		if (sp->mode != R2DP_MODE_TUNNEL && sp->mode != R2DP_MODE_TRANSPORT) return -EINVAL;
		memset(&t, 0, sizeof(t));
		if (sp->mode == R2DP_MODE_TUNNEL) {
			if (!fam_of(&sp->tun_src) || !fam_of(&sp->tun_dst)) return -EINVAL;
			put_addr(&t.saddr, &sp->tun_src); put_addr(&t.id.daddr, &sp->tun_dst);
		}
		t.id.proto = sp->protos == R2DP_SPP_AH ? R2DP_PROTO_AH : R2DP_PROTO_ESP;
		t.family = (uint16_t)fam;
		t.reqid = sp->reqid;
		t.mode = sp->mode == R2DP_MODE_TUNNEL ? XFRM_MODE_TUNNEL : XFRM_MODE_TRANSPORT;
		t.aalgos = t.ealgos = t.calgos = ~0u;
		t.optional = sp->level == R2DP_LVL_USE;
		if ((r = nlb_attr(&n, XFRMA_TMPL, &t, sizeof(t)))) return r;
	}
	r = nl_xfer(&n, why, sizeof(why));
	if (g_verbose)
		fprintf(stderr, "kfwd: UPDPOLICY slid=%u dir=%u action=%u -> %s%s%s\n", sp->slid, sp->dir, sp->action,
		        r ? strerror(-r) : "ok", why[0] ? ": " : "", why);
	return r;
}

static void sp_remove(const struct r2dp_sp *sp)
{
	struct xfrm_userpolicy_id id;
	struct nlb n;
	int d = xdir(sp->dir), r;

	if (d < 0) return;
	memset(&id, 0, sizeof(id));
	if (sp_fill_sel(&id.sel, sp) != 0) return;
	id.dir = (uint8_t)d;
	nlb_init(&n, XFRM_MSG_DELPOLICY, 0, &id, sizeof(id));
	r = nl_xfer(&n, NULL, 0);
	if (g_verbose) fprintf(stderr, "kfwd: DELPOLICY slid=%u -> %s\n", sp->slid, r ? strerror(-r) : "ok");
}

/* ----------------------------------------------------------------- hooks */
static int h_sa_set(void *c, const struct r2dp_sa *sa, const uint8_t *e, const uint8_t *a)
{ (void)c; return sa_install(sa, e, a); }
static void h_sa_del(void *c, const struct r2dp_sa *sa) { (void)c; sa_remove(sa); }
static int h_sp_set(void *c, const struct r2dp_sp *sp) { (void)c; return sp_install(sp); }
static void h_sp_del(void *c, const struct r2dp_sp *sp) { (void)c; sp_remove(sp); }

const struct r2dp_cp_hooks *kx_hooks(void)
{
	static const struct r2dp_cp_hooks h = { .sa_set = h_sa_set, .sa_del = h_sa_del,
	                                        .sp_set = h_sp_set, .sp_del = h_sp_del };
	return &h;
}

/* ---------------------------------------------------------------- caps */
static void cap_set(uint32_t bm[8], unsigned id) { bm[id >> 5] |= 1u << (id & 31); }

void kx_default_caps(struct r2dp_cp_caps *caps)
{
	memset(caps, 0, sizeof(*caps));
	caps->features = R2DP_FEAT_ESN | R2DP_FEAT_NATT | R2DP_FEAT_IPV6;
	cap_set(caps->integ_caps, R2DP_INTEG_NONE);
	for (unsigned i = 0; i < sizeof(enc_tab) / sizeof(enc_tab[0]); i++) cap_set(caps->enc_caps, enc_tab[i].id);
	for (unsigned i = 0; i < sizeof(integ_tab) / sizeof(integ_tab[0]); i++) cap_set(caps->integ_caps, integ_tab[i].id);
}

static int probe_one(uint8_t enc, uint8_t integ)
{
	struct r2dp_sa sa;
	uint8_t ek[R2DP_MAX_KEY], ak[R2DP_MAX_KEY];
	const struct enc_map *em = find_enc(enc);
	struct nlb n;
	int r;

	memset(&sa, 0, sizeof(sa)); memset(ek, 0x5a, sizeof(ek)); memset(ak, 0xa5, sizeof(ak));
	sa.src.family = sa.dst.family = R2DP_AF_INET4;           /* reserved TEST-NET-1 addresses */
	sa.src.addr[0] = 192; sa.src.addr[2] = 2; sa.src.addr[3] = 254;
	sa.dst.addr[0] = 192; sa.dst.addr[2] = 2; sa.dst.addr[3] = 253;
	sa.spi = htonl(0xfffffff0u); sa.proto = R2DP_PROTO_ESP; sa.mode = R2DP_MODE_TUNNEL;
	sa.enc = enc; sa.integ = integ; sa.wsize = 64;
	if (em && em->aead) sa.enckeylen = (uint16_t)(enc == R2DP_ENCR_CHACHA20_POLY1305 ? 36 :
	                                           (em->name[6] == '3' ? 19 : 20));         /* ccm: 16+3, gcm: 16+4 */
	else if (enc == R2DP_ENCR_3DES) sa.enckeylen = 24;
	else if (enc == R2DP_ENCR_NULL) sa.enckeylen = 0;
	else sa.enckeylen = 16;
	if (integ) {
		sa.authkeylen = integ == R2DP_INTEG_HMAC_MD5_96 ? 16 : integ == R2DP_INTEG_HMAC_SHA1_96 ? 20 :
		                integ == R2DP_INTEG_HMAC_SHA2_256_128 ? 32 : integ == R2DP_INTEG_HMAC_SHA2_384_192 ? 48 :
		                integ == R2DP_INTEG_HMAC_SHA2_512_256 ? 64 : 16;
	}
	if (build_sa(&n, XFRM_MSG_NEWSA, 0, &sa, ek, ak)) return 0;
	r = nl_xfer(&n, NULL, 0);
	if (r == 0) sa_remove(&sa);
	return r == 0;
}

int kx_probe_caps(struct r2dp_cp_caps *caps)
{
	int ok = 0, v = g_verbose;
	g_verbose = 0;
	memset(caps, 0, sizeof(*caps));
	cap_set(caps->integ_caps, R2DP_INTEG_NONE);
	for (unsigned i = 0; i < sizeof(enc_tab) / sizeof(enc_tab[0]); i++) {
		const struct enc_map *e = &enc_tab[i];
		/* AEAD needs no integrity; others are probed with HMAC-SHA1 (NULL cipher included) */
		if (probe_one(e->id, e->aead ? R2DP_INTEG_NONE : R2DP_INTEG_HMAC_SHA1_96)) { cap_set(caps->enc_caps, e->id); ok++; }
	}
	for (unsigned i = 0; i < sizeof(integ_tab) / sizeof(integ_tab[0]); i++)
		if (probe_one(R2DP_ENCR_AES_CBC, integ_tab[i].id)) { cap_set(caps->integ_caps, integ_tab[i].id); ok++; }
	if (ok) caps->features = R2DP_FEAT_ESN | R2DP_FEAT_NATT | R2DP_FEAT_IPV6;
	g_verbose = v;
	return ok;
}

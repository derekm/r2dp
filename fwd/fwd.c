/*
 * r2dp-fwd: DPDK IPsec forwarder driven by the r2dp control protocol.
 *
 * M1 scope: one lcore, two ports (black = ESP/untrusted side, red = clear
 * side), IPv4 ESP tunnel mode, AES-GCM-16 through rte_cryptodev, SAD in an
 * rte_hash, SPD in rte_acl, static routes in rte_lpm.  Run-to-completion:
 * each burst is classified, encrypted/decrypted synchronously, and sent.
 *
 *   r2dp-fwd [EAL options] -- --sock PATH --local IPV4
 *            --route CIDR,black|red,MAC ... [--idle-us N] [-v]
 *
 * Exception path: if a third port (e.g. --vdev net_tap0,iface=r2tap0) exists, it
 * is given the black port's MAC and carries everything the black side addresses
 * to the gateway itself -- ARP, IKE (UDP 500/4500), ICMP -- to the kernel, and
 * whatever the kernel sends back out of the black port.  iked/spmd then run on
 * that TAP interface as on any host.  ESP for local SAs stays on the fast path.
 *
 * The ESP framing, sequence numbers and anti-replay window are implemented
 * here (not librte_ipsec) so M2 can add ESN, lifetimes and counters without
 * depending on that library's private op layout.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_acl.h>
#include <rte_common.h>
#include <rte_cryptodev.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_lpm.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_cycles.h>

#include "r2dp/cp.h"

#define BURST       32
#define SAD_ENTRIES 2048
#define MAX_SP      1024
#define MAX_RT      64
#define ETH_LEN     sizeof(struct rte_ether_hdr)
#define ESP_HLEN    8                    /* SPI + SEQ */
#define ESP_IV_LEN  8                    /* explicit IV (RFC 4106) */
#define ESP_OVH     (sizeof(struct rte_ipv4_hdr) + ESP_HLEN + ESP_IV_LEN)
#define ICV_LEN     16                   /* AES-GCM-16 */
#define GCM_NONCE   12
#define IV_OFFSET   (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))
#define AAD_OFFSET  (IV_OFFSET + 16)
#define META_OFFSET (AAD_OFFSET + 16)
#define OP_PRIV     48
#define PORT_BLACK  0
#define PORT_RED    1
#define PORT_TAP    2                    /* optional exception path to the kernel (IKE, ARP, ICMP) */

/* ------------------------------------------------------------------ state */
struct fwd_sa {
	int used, inbound;
	uint32_t src, dst, spi;              /* network order, as on the wire */
	uint8_t salt[4];
	struct rte_cryptodev_sym_session *sess;
	uint64_t gen;                        /* install order: newest wins on rekey */
	uint64_t seq;                        /* outbound: last sequence used */
	uint64_t rp_top, rp_bmp;             /* inbound replay window (64) */
	uint64_t pkts, bytes;
};

struct fwd_sp {
	int used, v4;
	struct r2dp_sp sp;
	int sa_idx;                          /* outbound binding, -1 = none */
};

struct fwd_route { uint16_t port; struct rte_ether_addr mac; };

struct fwd_stats {
	uint64_t rx[3], tx[3];
	uint64_t exc_in, exc_out;           /* black->kernel, kernel->black */
	uint64_t esp_out, esp_in, bypass, discard;
	uint64_t drop_not_us, drop_non_ip, drop_bad_ip, drop_ttl, drop_no_route;
	uint64_t drop_no_sa, drop_no_sp_sa, drop_auth, drop_replay, drop_bad_esp;
	uint64_t drop_policy, drop_local, drop_too_big, drop_seq, drop_nobuf, drop_crypto;
};

static struct {
	uint32_t local_ip;                   /* network order */
	int idle_us, verbose;
	uint8_t cdev;
	struct rte_ether_addr mac[3];
	int has_tap;
	struct rte_mempool *pkt_pool, *op_pool, *sess_pool;
	struct rte_hash *sad;
	struct fwd_sa sa[SAD_ENTRIES];
	struct fwd_sp sp[MAX_SP];
	struct rte_acl_ctx *acl_out, *acl_in;
	unsigned acl_gen;
	uint64_t sa_gen;
	struct rte_lpm *lpm;
	struct fwd_route rt[MAX_RT];
	int nrt;
	struct fwd_stats st;
} G;

static volatile sig_atomic_t g_stop, g_dump;

/* Per-drop diagnostics, only with -v (never on the fast path otherwise). */
#define DROPLOG(...) do { if (G.verbose) { fprintf(stderr, "fwd: drop: " __VA_ARGS__); fputc('\n', stderr); } } while (0)

struct hkey { uint32_t spi, dst; };

/* ------------------------------------------------------------------ ACL */
enum { F_PROTO, F_SRC, F_DST, F_SPORT, F_DPORT, NFIELDS };
struct key4 { uint8_t proto, pad[3]; uint32_t src, dst; uint16_t sport, dport; }; /* network order */
RTE_ACL_RULE_DEF(acl_rule, NFIELDS);

static const struct rte_acl_field_def acl_defs[NFIELDS] = {
	{ .type = RTE_ACL_FIELD_TYPE_BITMASK, .size = 1, .field_index = F_PROTO, .input_index = 0,
	  .offset = offsetof(struct key4, proto) },
	{ .type = RTE_ACL_FIELD_TYPE_MASK, .size = 4, .field_index = F_SRC, .input_index = 1,
	  .offset = offsetof(struct key4, src) },
	{ .type = RTE_ACL_FIELD_TYPE_MASK, .size = 4, .field_index = F_DST, .input_index = 2,
	  .offset = offsetof(struct key4, dst) },
	{ .type = RTE_ACL_FIELD_TYPE_RANGE, .size = 2, .field_index = F_SPORT, .input_index = 3,
	  .offset = offsetof(struct key4, sport) },
	{ .type = RTE_ACL_FIELD_TYPE_RANGE, .size = 2, .field_index = F_DPORT, .input_index = 3,
	  .offset = offsetof(struct key4, dport) },
};

static struct acl_rule g_rules[MAX_SP];

static uint32_t be32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return rte_be_to_cpu_32(v); }

/* More specific selectors win: protocol, ports, then prefix lengths. */
static int sp_priority(const struct r2dp_sp *sp)
{
	return 1 + sp->pref_src + sp->pref_dst + (sp->ul_proto != R2DP_PROTO_ANY ? 100 : 0) +
	       (sp->sel_src.port ? 50 : 0) + (sp->sel_dst.port ? 50 : 0);
}

/* Returns 0 and sets *ctxp (NULL when there are simply no rules), or -1 on failure. */
static int build_acl(int out, struct rte_acl_ctx **ctxp)
{
	struct rte_acl_param prm;
	struct rte_acl_config cfg;
	struct rte_acl_ctx *ctx;
	char name[RTE_ACL_NAMESIZE];
	int n = 0;

	for (int i = 0; i < MAX_SP; i++) {
		const struct fwd_sp *s = &G.sp[i];
		struct acl_rule *r;
		uint16_t sp_lo, sp_hi, dp_lo, dp_hi;

		if (!s->used || !s->v4) continue;
		if (out ? s->sp.dir != R2DP_DIR_OUT : s->sp.dir == R2DP_DIR_OUT) continue;
		r = &g_rules[n++];
		memset(r, 0, sizeof(*r));
		r->data.category_mask = 1;
		r->data.priority = sp_priority(&s->sp);
		r->data.userdata = (uint32_t)i + 1;
		r->field[F_PROTO].value.u8 = s->sp.ul_proto == R2DP_PROTO_ANY ? 0 : s->sp.ul_proto;
		r->field[F_PROTO].mask_range.u8 = s->sp.ul_proto == R2DP_PROTO_ANY ? 0 : 0xff;
		r->field[F_SRC].value.u32 = be32(s->sp.sel_src.addr);
		r->field[F_SRC].mask_range.u32 = s->sp.pref_src;
		r->field[F_DST].value.u32 = be32(s->sp.sel_dst.addr);
		r->field[F_DST].mask_range.u32 = s->sp.pref_dst;
		sp_lo = sp_hi = rte_be_to_cpu_16(s->sp.sel_src.port);
		dp_lo = dp_hi = rte_be_to_cpu_16(s->sp.sel_dst.port);
		if (!s->sp.sel_src.port) { sp_lo = 0; sp_hi = 0xffff; }
		if (!s->sp.sel_dst.port) { dp_lo = 0; dp_hi = 0xffff; }
		r->field[F_SPORT].value.u16 = sp_lo; r->field[F_SPORT].mask_range.u16 = sp_hi;
		r->field[F_DPORT].value.u16 = dp_lo; r->field[F_DPORT].mask_range.u16 = dp_hi;
	}
	*ctxp = NULL;
	if (!n) return 0;
	snprintf(name, sizeof(name), "acl_%s_%u", out ? "out" : "in", G.acl_gen++);
	memset(&prm, 0, sizeof(prm));
	prm.name = name; prm.socket_id = SOCKET_ID_ANY;
	prm.rule_size = RTE_ACL_RULE_SZ(NFIELDS); prm.max_rule_num = n;
	if (!(ctx = rte_acl_create(&prm))) return -1;
	if (rte_acl_add_rules(ctx, (struct rte_acl_rule *)g_rules, n) != 0) { rte_acl_free(ctx); return -1; }
	memset(&cfg, 0, sizeof(cfg));
	cfg.num_categories = 1; cfg.num_fields = NFIELDS;
	memcpy(cfg.defs, acl_defs, sizeof(acl_defs));
	if (rte_acl_build(ctx, &cfg) != 0) { rte_acl_free(ctx); return -1; }
	*ctxp = ctx;
	return 0;
}

/* ------------------------------------------------------- SAD / SPD tables */
static void rebind(void)
{
	for (int i = 0; i < MAX_SP; i++) {
		struct fwd_sp *s = &G.sp[i];
		uint32_t ts, td;
		uint64_t best = 0;

		s->sa_idx = -1;
		if (!s->used || !s->v4 || s->sp.action != R2DP_ACT_PROTECT) continue;
		memcpy(&ts, s->sp.tun_src.addr, 4); memcpy(&td, s->sp.tun_dst.addr, 4);
		for (int j = 0; j < SAD_ENTRIES; j++) {
			const struct fwd_sa *a = &G.sa[j];
			if (a->used && !a->inbound && a->src == ts && a->dst == td && a->gen >= best) {
				best = a->gen; s->sa_idx = j;
			}
		}
	}
}

/*
 * Build both contexts first and swap only if both succeed.  On failure the old
 * contexts stay in force and the caller rolls its table change back, so a
 * failed rebuild can never turn into "no policy" (= forward in the clear).
 */
static int rebuild_acls(void)
{
	struct rte_acl_ctx *no = NULL, *ni = NULL;

	if (build_acl(1, &no) < 0 || build_acl(0, &ni) < 0) {
		if (no) rte_acl_free(no);
		if (ni) rte_acl_free(ni);
		return -1;
	}
	if (G.acl_out) rte_acl_free(G.acl_out);
	if (G.acl_in) rte_acl_free(G.acl_in);
	G.acl_out = no; G.acl_in = ni;
	rebind();
	return 0;
}

static int hook_sa_set(void *ctx, const struct r2dp_sa *sa, const uint8_t *enc, const uint8_t *auth)
{
	struct rte_crypto_sym_xform xf;
	struct hkey k;
	struct fwd_sa *e;
	struct rte_cryptodev_sym_session *sess;
	uint32_t src, dst;
	int pos, inbound;
	unsigned klen;
	(void)ctx; (void)auth;

	if (sa->proto != R2DP_PROTO_ESP) return -EOPNOTSUPP;
	if (sa->mode != R2DP_MODE_TUNNEL) return -EOPNOTSUPP;
	if (sa->enc != R2DP_ENCR_AES_GCM_16 || sa->integ != R2DP_INTEG_NONE) return -EOPNOTSUPP;
	if (sa->saflags & R2DP_SAF_ESN) return -EOPNOTSUPP;          /* M2 */
	if (sa->natt_type != R2DP_NATT_NONE) return -EOPNOTSUPP;     /* M2 */
	if (sa->src.family != R2DP_AF_INET4 || sa->dst.family != R2DP_AF_INET4) return -EAFNOSUPPORT;
	if (sa->enckeylen != 20 && sa->enckeylen != 36) return -EINVAL;   /* key || 4-byte salt */
	klen = sa->enckeylen - 4;
	memcpy(&src, sa->src.addr, 4); memcpy(&dst, sa->dst.addr, 4);
	inbound = (dst == G.local_ip);

	memset(&xf, 0, sizeof(xf));
	xf.type = RTE_CRYPTO_SYM_XFORM_AEAD;
	xf.aead.op = inbound ? RTE_CRYPTO_AEAD_OP_DECRYPT : RTE_CRYPTO_AEAD_OP_ENCRYPT;
	xf.aead.algo = RTE_CRYPTO_AEAD_AES_GCM;
	xf.aead.key.data = enc; xf.aead.key.length = klen;
	xf.aead.iv.offset = IV_OFFSET; xf.aead.iv.length = GCM_NONCE;
	xf.aead.digest_length = ICV_LEN; xf.aead.aad_length = ESP_HLEN;
	if (!(sess = rte_cryptodev_sym_session_create(G.cdev, &xf, G.sess_pool))) return -EOPNOTSUPP;

	k.spi = sa->spi; k.dst = dst;
	pos = rte_hash_lookup(G.sad, &k);
	if (pos < 0) {
		if ((pos = rte_hash_add_key(G.sad, &k)) < 0) { rte_cryptodev_sym_session_free(G.cdev, sess); return -ENOBUFS; }
		memset(&G.sa[pos], 0, sizeof(G.sa[pos]));
	} else if (G.sa[pos].sess) {
		rte_cryptodev_sym_session_free(G.cdev, G.sa[pos].sess);   /* key refresh: keep counters */
	}
	e = &G.sa[pos];
	e->used = 1; e->inbound = inbound; e->src = src; e->dst = dst; e->spi = sa->spi;
	memcpy(e->salt, enc + klen, 4);
	e->sess = sess;
	if (!e->gen) e->gen = ++G.sa_gen;
	rebind();
	if (G.verbose) fprintf(stderr, "fwd: SA %s spi=0x%08x installed\n", inbound ? "in" : "out", rte_be_to_cpu_32(sa->spi));
	return 0;
}

static void hook_sa_del(void *ctx, const struct r2dp_sa *sa)
{
	struct hkey k;
	int pos;
	uint32_t dst;
	(void)ctx;
	if (sa->dst.family != R2DP_AF_INET4) return;
	memcpy(&dst, sa->dst.addr, 4);
	k.spi = sa->spi; k.dst = dst;
	if ((pos = rte_hash_lookup(G.sad, &k)) < 0) return;
	if (G.sa[pos].sess) rte_cryptodev_sym_session_free(G.cdev, G.sa[pos].sess);
	memset(&G.sa[pos], 0, sizeof(G.sa[pos]));
	rte_hash_del_key(G.sad, &k);
	rebind();
}

static int sp_slot(uint32_t slid, int create)
{
	int freeslot = -1;
	for (int i = 0; i < MAX_SP; i++) {
		if (G.sp[i].used && G.sp[i].sp.slid == slid) return i;
		if (!G.sp[i].used && freeslot < 0) freeslot = i;
	}
	return create ? freeslot : -1;
}

static int hook_sp_set(void *ctx, const struct r2dp_sp *sp)
{
	int i = sp_slot(sp->slid, 1);
	struct fwd_sp prev;
	int v4;
	(void)ctx;
	if (i < 0) return -ENOBUFS;

	/* Validate everything BEFORE touching the table: a rejected update must leave
	 * the previously installed policy exactly as it was. */
	v4 = sp->sel_src.family == R2DP_AF_INET4 && sp->sel_dst.family == R2DP_AF_INET4;
	if (v4 && sp->action == R2DP_ACT_PROTECT &&
	    (sp->mode != R2DP_MODE_TUNNEL || sp->protos != R2DP_SPP_ESP ||
	     sp->tun_src.family != R2DP_AF_INET4 || sp->tun_dst.family != R2DP_AF_INET4))
		return -EOPNOTSUPP;

	prev = G.sp[i];
	G.sp[i].used = 1; G.sp[i].sp = *sp;
	/* Non-IPv4 policies are kept but not programmed: the datapath drops all
	 * non-IPv4 traffic, so this fails closed rather than open. */
	G.sp[i].v4 = v4;
	if (rebuild_acls() < 0) { G.sp[i] = prev; return -ENOMEM; }
	return 0;
}

static void hook_sp_del(void *ctx, const struct r2dp_sp *sp)
{
	int i = sp_slot(sp->slid, 0);
	(void)ctx;
	if (i >= 0) {
		struct fwd_sp prev = G.sp[i];
		G.sp[i].used = 0;
		if (rebuild_acls() < 0) {          /* keep enforcing the old (stricter or equal) rules rather than none */
			G.sp[i] = prev; G.sp[i].used = 0;
			fprintf(stderr, "fwd: warning: SPD rebuild failed on delete; stale policy %u stays enforced\n", sp->slid);
		}
	}
}

/* ----------------------------------------------------------------- routes */
static int add_route(const char *spec)
{
	char buf[128], *cidr, *port, *mac, *sl;
	uint32_t ip; uint8_t depth = 32;
	struct fwd_route *r;
	struct in_addr a;

	snprintf(buf, sizeof(buf), "%s", spec);
	cidr = strtok(buf, ","); port = strtok(NULL, ","); mac = strtok(NULL, ",");
	if (!cidr || !port || !mac || G.nrt >= MAX_RT) return -1;
	if ((sl = strchr(cidr, '/'))) { *sl++ = 0; depth = (uint8_t)atoi(sl); }
	if (inet_pton(AF_INET, cidr, &a) != 1) return -1;
	r = &G.rt[G.nrt];
	r->port = !strcmp(port, "black") ? PORT_BLACK : !strcmp(port, "red") ? PORT_RED : 99;
	if (r->port == 99) return -1;
	if (sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &r->mac.addr_bytes[0], &r->mac.addr_bytes[1],
	           &r->mac.addr_bytes[2], &r->mac.addr_bytes[3], &r->mac.addr_bytes[4], &r->mac.addr_bytes[5]) != 6)
		return -1;
	ip = rte_be_to_cpu_32(a.s_addr);
	if (rte_lpm_add(G.lpm, ip, depth, (uint32_t)G.nrt) != 0) return -1;
	G.nrt++;
	return 0;
}

static const struct fwd_route *route_lookup(uint32_t dst_be)
{
	uint32_t nh;
	if (rte_lpm_lookup(G.lpm, rte_be_to_cpu_32(dst_be), &nh) != 0) return NULL;
	return &G.rt[nh];
}

/* ---------------------------------------------------------------- packets */
struct txq { struct rte_mbuf *m[BURST * 2]; unsigned n; };
static struct txq txq[3];

static void tx_queue(const struct fwd_route *rt, struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, ETH_LEN);
	struct txq *q = &txq[rt->port];
	if (!eth || q->n >= RTE_DIM(q->m)) { rte_pktmbuf_free(m); G.st.drop_nobuf++; return; }
	rte_ether_addr_copy(&rt->mac, &eth->dst_addr);
	rte_ether_addr_copy(&G.mac[rt->port], &eth->src_addr);
	eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	q->m[q->n++] = m;
}

/* Send a frame exactly as received (exception path): no L2 rewrite. */
static void tx_raw(unsigned port, struct rte_mbuf *m)
{
	struct txq *q = &txq[port];
	if (q->n >= RTE_DIM(q->m)) { rte_pktmbuf_free(m); G.st.drop_nobuf++; return; }
	q->m[q->n++] = m;
}

static void tx_flush(void)
{
	for (int p = 0; p < 3; p++) {
		struct txq *q = &txq[p];
		uint16_t sent;
		if (!q->n) continue;
		sent = rte_eth_tx_burst((uint16_t)p, 0, q->m, (uint16_t)q->n);
		G.st.tx[p] += sent;
		for (unsigned i = sent; i < q->n; i++) { rte_pktmbuf_free(q->m[i]); G.st.drop_nobuf++; }
		q->n = 0;
	}
}

static void ip_fixup_ttl(struct rte_ipv4_hdr *ip)
{
	ip->time_to_live--;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
}

/* Validate the IPv4 header at the start of m's data; trims L2 padding. */
static struct rte_ipv4_hdr *ip_check(struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ip;
	unsigned hl, tot;

	if (m->nb_segs != 1 || m->data_len < sizeof(*ip)) return NULL;
	ip = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
	hl = (ip->version_ihl & 0x0f) * 4u;
	if ((ip->version_ihl >> 4) != 4 || hl < sizeof(*ip) || m->data_len < hl) return NULL;
	tot = rte_be_to_cpu_16(ip->total_length);
	if (tot < hl || tot > m->pkt_len) return NULL;
	if (tot < m->pkt_len) rte_pktmbuf_trim(m, m->pkt_len - tot);
	return ip;
}

static void fill_key(struct key4 *k, const struct rte_ipv4_hdr *ip, const struct rte_mbuf *m)
{
	unsigned hl = (ip->version_ihl & 0x0f) * 4u;
	memset(k, 0, sizeof(*k));
	k->proto = ip->next_proto_id; k->src = ip->src_addr; k->dst = ip->dst_addr;
	if ((ip->next_proto_id == IPPROTO_TCP || ip->next_proto_id == IPPROTO_UDP) &&
	    !(ip->fragment_offset & rte_cpu_to_be_16(RTE_IPV4_HDR_OFFSET_MASK | RTE_IPV4_HDR_MF_FLAG)) &&
	    m->data_len >= hl + 4u) {
		const uint16_t *p = (const uint16_t *)((const uint8_t *)ip + hl);
		k->sport = p[0]; k->dport = p[1];
	}
}

static const struct fwd_sp *spd_lookup(struct rte_acl_ctx *ctx, const struct key4 *k)
{
	const uint8_t *data[1] = { (const uint8_t *)k };
	uint32_t res = 0;
	if (!ctx) return NULL;
	if (rte_acl_classify(ctx, data, &res, 1, 1) != 0 || !res) return NULL;
	return &G.sp[res - 1];
}

/* ------------------------------------------------- crypto op batch helper */
struct opmeta { struct fwd_sa *sa; const struct fwd_route *rt; };

static struct rte_crypto_op *op_new(struct rte_mbuf *m, struct fwd_sa *sa, const struct fwd_route *rt)
{
	struct rte_crypto_op *op = rte_crypto_op_alloc(G.op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	struct opmeta *meta;
	if (!op) return NULL;
	rte_crypto_op_attach_sym_session(op, sa->sess);
	op->sym->m_src = m; op->sym->m_dst = NULL;
	meta = rte_crypto_op_ctod_offset(op, struct opmeta *, META_OFFSET);
	meta->sa = sa; meta->rt = rt;
	return op;
}

/* Enqueue ops and spin until every one has come back (SW PMDs are synchronous). */
static unsigned crypto_run(struct rte_crypto_op **ops, unsigned n, struct rte_crypto_op **done)
{
	unsigned enq = rte_cryptodev_enqueue_burst(G.cdev, 0, ops, (uint16_t)n), got = 0, spins = 0;
	for (unsigned i = enq; i < n; i++) {         /* queue full: fail those */
		ops[i]->status = RTE_CRYPTO_OP_STATUS_ERROR;
		done[got++] = ops[i];
	}
	for (unsigned want = enq; want && spins < 1000000; spins++) {
		unsigned d = rte_cryptodev_dequeue_burst(G.cdev, 0, done + got, (uint16_t)want);
		got += d; want -= d;
	}
	return got;
}

/* ------------------------------------------------------------ red -> black */
static void handle_red(struct rte_mbuf **pk, unsigned n)
{
	struct rte_crypto_op *ops[BURST], *done[BURST];
	unsigned nops = 0;

	for (unsigned i = 0; i < n; i++) {
		struct rte_mbuf *m = pk[i];
		struct rte_ether_hdr *eth;
		struct rte_ipv4_hdr *ip;
		const struct fwd_route *rt;
		const struct fwd_sp *sp;
		struct key4 key;

		G.st.rx[PORT_RED]++;
		if (m->data_len < ETH_LEN) { rte_pktmbuf_free(m); G.st.drop_non_ip++; continue; }
		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		if (!rte_is_same_ether_addr(&eth->dst_addr, &G.mac[PORT_RED])) { rte_pktmbuf_free(m); G.st.drop_not_us++; continue; }
		if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) { rte_pktmbuf_free(m); G.st.drop_non_ip++; continue; }
		rte_pktmbuf_adj(m, ETH_LEN);
		if (!(ip = ip_check(m))) { rte_pktmbuf_free(m); G.st.drop_bad_ip++; continue; }
		if (ip->time_to_live <= 1) { rte_pktmbuf_free(m); G.st.drop_ttl++; continue; }

		fill_key(&key, ip, m);
		sp = spd_lookup(G.acl_out, &key);
		if (sp && sp->sp.action == R2DP_ACT_DISCARD) { rte_pktmbuf_free(m); G.st.discard++; continue; }
		if (!sp || sp->sp.action == R2DP_ACT_BYPASS) {          /* no policy => forward clear, as the kernel does */
			if (!(rt = route_lookup(ip->dst_addr))) { rte_pktmbuf_free(m); G.st.drop_no_route++; continue; }
			ip_fixup_ttl(ip); G.st.bypass++;
			tx_queue(rt, m);
			continue;
		}
		/* PROTECT: ESP tunnel encapsulation */
		{
			struct fwd_sa *sa;
			struct rte_crypto_op *op;
			struct rte_ipv4_hdr *o;
			uint8_t *h, *t, *iv, *aad;
			uint16_t inner = rte_be_to_cpu_16(ip->total_length);
			unsigned pad = (4u - ((inner + 2u) & 3u)) & 3u, doff = ESP_OVH, dlen = inner + pad + 2u;
			uint64_t seq;

			if (sp->sa_idx < 0) { rte_pktmbuf_free(m); G.st.drop_no_sp_sa++; continue; }   /* M4: ACQUIRE */
			sa = &G.sa[sp->sa_idx];
			if (!(rt = route_lookup(sa->dst))) { rte_pktmbuf_free(m); G.st.drop_no_route++; continue; }
			if (inner + ESP_OVH + pad + 2u + ICV_LEN > RTE_ETHER_MTU) { rte_pktmbuf_free(m); G.st.drop_too_big++; continue; }
			if ((seq = sa->seq + 1) > 0xffffffffull) { rte_pktmbuf_free(m); G.st.drop_seq++; continue; }
			ip_fixup_ttl(ip);
			if (!(t = (uint8_t *)rte_pktmbuf_append(m, pad + 2 + ICV_LEN))) { rte_pktmbuf_free(m); G.st.drop_nobuf++; continue; }
			for (unsigned j = 0; j < pad; j++) t[j] = (uint8_t)(j + 1);
			t[pad] = (uint8_t)pad; t[pad + 1] = IPPROTO_IPIP;
			if (!(h = (uint8_t *)rte_pktmbuf_prepend(m, ESP_OVH))) { rte_pktmbuf_free(m); G.st.drop_nobuf++; continue; }
			sa->seq = seq;
			o = (struct rte_ipv4_hdr *)h;
			memset(o, 0, sizeof(*o));
			o->version_ihl = 0x45;
			o->type_of_service = ((struct rte_ipv4_hdr *)(h + ESP_OVH))->type_of_service;
			o->total_length = rte_cpu_to_be_16((uint16_t)m->pkt_len);
			o->packet_id = rte_cpu_to_be_16((uint16_t)seq);
			o->time_to_live = 64; o->next_proto_id = IPPROTO_ESP;
			o->src_addr = sa->src; o->dst_addr = sa->dst;
			o->hdr_checksum = rte_ipv4_cksum(o);
			{ uint32_t s32 = rte_cpu_to_be_32((uint32_t)seq); uint64_t s64 = rte_cpu_to_be_64(seq);
			  memcpy(h + 20, &sa->spi, 4); memcpy(h + 24, &s32, 4); memcpy(h + 28, &s64, 8); }

			if (!(op = op_new(m, sa, rt))) { rte_pktmbuf_free(m); G.st.drop_nobuf++; continue; }
			op->sym->aead.data.offset = (uint32_t)doff;
			op->sym->aead.data.length = dlen;
			op->sym->aead.digest.data = rte_pktmbuf_mtod_offset(m, uint8_t *, doff + dlen);
			op->sym->aead.digest.phys_addr = rte_pktmbuf_iova_offset(m, doff + dlen);
			iv = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
			memcpy(iv, sa->salt, 4); memcpy(iv + 4, h + 28, 8);
			aad = rte_crypto_op_ctod_offset(op, uint8_t *, AAD_OFFSET);
			memcpy(aad, h + 20, ESP_HLEN);
			op->sym->aead.aad.data = aad;
			op->sym->aead.aad.phys_addr = rte_crypto_op_ctophys_offset(op, AAD_OFFSET);
			ops[nops++] = op;
		}
	}
	if (nops) {
		unsigned got = crypto_run(ops, nops, done);
		for (unsigned i = 0; i < got; i++) {
			struct rte_crypto_op *op = done[i];
			struct rte_mbuf *m = op->sym->m_src;
			struct opmeta *meta = rte_crypto_op_ctod_offset(op, struct opmeta *, META_OFFSET);
			if (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) { rte_pktmbuf_free(m); G.st.drop_crypto++; }
			else { meta->sa->pkts++; meta->sa->bytes += m->pkt_len; G.st.esp_out++; tx_queue(meta->rt, m); }
			rte_crypto_op_free(op);
		}
	}
}

/* ------------------------------------------------------------ black -> red */
static int replay_ok(const struct fwd_sa *sa, uint64_t seq)
{
	if (!seq) return 0;
	if (seq > sa->rp_top) return 1;
	if (sa->rp_top - seq >= 64) return 0;
	return !((sa->rp_bmp >> (sa->rp_top - seq)) & 1);
}
static void replay_update(struct fwd_sa *sa, uint64_t seq)
{
	if (seq > sa->rp_top) {
		uint64_t sh = seq - sa->rp_top;
		sa->rp_bmp = sh >= 64 ? 0 : sa->rp_bmp << sh;
		sa->rp_bmp |= 1; sa->rp_top = seq;
	} else {
		sa->rp_bmp |= 1ull << (sa->rp_top - seq);
	}
}

static void handle_black(struct rte_mbuf **pk, unsigned n)
{
	struct rte_crypto_op *ops[BURST], *done[BURST];
	uint64_t seqs[BURST];                         /* indexed by op position */
	unsigned nops = 0;

	for (unsigned i = 0; i < n; i++) {
		struct rte_mbuf *m = pk[i];
		struct rte_ether_hdr *eth;
		struct rte_ipv4_hdr *ip;

		G.st.rx[PORT_BLACK]++;
		if (m->data_len < ETH_LEN) { rte_pktmbuf_free(m); G.st.drop_non_ip++; continue; }
		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		{
			int mine = rte_is_same_ether_addr(&eth->dst_addr, &G.mac[PORT_BLACK]);
			int bcast = rte_is_multicast_ether_addr(&eth->dst_addr);   /* includes broadcast */
			int v4 = eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

			if (!mine && !bcast) { rte_pktmbuf_free(m); G.st.drop_not_us++; continue; }
			/* Exception path: non-IPv4 (ARP...) and anything addressed to the gateway
			 * itself that is not ESP.  Broadcasts only qualify when they are ARP. */
			if (!v4) {
				if ((mine || eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) && G.has_tap) {
					G.st.exc_in++; tx_raw(PORT_TAP, m);
				} else { rte_pktmbuf_free(m); G.st.drop_non_ip++; }
				continue;
			}
			if (!mine) { rte_pktmbuf_free(m); G.st.drop_not_us++; continue; }   /* IP broadcast/multicast: not handled */
			if (m->data_len >= ETH_LEN + sizeof(struct rte_ipv4_hdr)) {
				const struct rte_ipv4_hdr *pip = (const struct rte_ipv4_hdr *)(eth + 1);
				if (pip->dst_addr == G.local_ip && pip->next_proto_id != IPPROTO_ESP && G.has_tap) {
					G.st.exc_in++; tx_raw(PORT_TAP, m);
					continue;
				}
			}
		}
		rte_pktmbuf_adj(m, ETH_LEN);
		if (!(ip = ip_check(m))) { rte_pktmbuf_free(m); G.st.drop_bad_ip++; continue; }

		if (ip->next_proto_id == IPPROTO_ESP && ip->dst_addr == G.local_ip) {
			unsigned hl = (ip->version_ihl & 0x0f) * 4u, tot = rte_be_to_cpu_16(ip->total_length), enc_len;
			const uint8_t *esp = (const uint8_t *)ip + hl;
			struct hkey k; int pos;
			struct fwd_sa *sa;
			struct rte_crypto_op *op;
			uint8_t *iv, *aad;
			uint32_t seq32;

			if (tot < hl + ESP_HLEN + ESP_IV_LEN + ICV_LEN + 4) { rte_pktmbuf_free(m); G.st.drop_bad_esp++; continue; }
			memcpy(&k.spi, esp, 4); k.dst = ip->dst_addr;
			if ((pos = rte_hash_lookup(G.sad, &k)) < 0 || !G.sa[pos].inbound) { rte_pktmbuf_free(m); G.st.drop_no_sa++; continue; }
			sa = &G.sa[pos];
			memcpy(&seq32, esp + 4, 4); seq32 = rte_be_to_cpu_32(seq32);
			if (!replay_ok(sa, seq32)) {
				DROPLOG("replay(pre) spi=0x%08x seq=%u top=%lu", rte_be_to_cpu_32(sa->spi), seq32, sa->rp_top);
				rte_pktmbuf_free(m); G.st.drop_replay++; continue;
			}
			enc_len = tot - hl - ESP_HLEN - ESP_IV_LEN - ICV_LEN;
			if (enc_len & 3u) { rte_pktmbuf_free(m); G.st.drop_bad_esp++; continue; }
			if (!(op = op_new(m, sa, NULL))) { rte_pktmbuf_free(m); G.st.drop_nobuf++; continue; }
			op->sym->aead.data.offset = hl + ESP_HLEN + ESP_IV_LEN;
			op->sym->aead.data.length = enc_len;
			op->sym->aead.digest.data = rte_pktmbuf_mtod_offset(m, uint8_t *, tot - ICV_LEN);
			op->sym->aead.digest.phys_addr = rte_pktmbuf_iova_offset(m, tot - ICV_LEN);
			iv = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
			memcpy(iv, sa->salt, 4); memcpy(iv + 4, esp + ESP_HLEN, ESP_IV_LEN);
			aad = rte_crypto_op_ctod_offset(op, uint8_t *, AAD_OFFSET);
			memcpy(aad, esp, ESP_HLEN);
			op->sym->aead.aad.data = aad;
			op->sym->aead.aad.phys_addr = rte_crypto_op_ctophys_offset(op, AAD_OFFSET);
			seqs[nops] = seq32;
			ops[nops++] = op;
			continue;
		}

		/* not ESP for us */
		if (ip->dst_addr == G.local_ip) { rte_pktmbuf_free(m); G.st.drop_local++; continue; }   /* M1B: TAP exception path */
		{
			struct key4 key; const struct fwd_sp *sp; const struct fwd_route *rt;
			fill_key(&key, ip, m);
			sp = spd_lookup(G.acl_in, &key);
			if (sp && sp->sp.action == R2DP_ACT_DISCARD) { rte_pktmbuf_free(m); G.st.discard++; continue; }
			if (sp && sp->sp.action == R2DP_ACT_PROTECT) { rte_pktmbuf_free(m); G.st.drop_policy++; continue; } /* clear where ESP required */
			if (ip->time_to_live <= 1) { rte_pktmbuf_free(m); G.st.drop_ttl++; continue; }
			if (!(rt = route_lookup(ip->dst_addr))) { rte_pktmbuf_free(m); G.st.drop_no_route++; continue; }
			ip_fixup_ttl(ip); G.st.bypass++;
			tx_queue(rt, m);
		}
	}
	if (!nops) return;
	{
		unsigned got = crypto_run(ops, nops, done);
		for (unsigned i = 0; i < got; i++) {
			struct rte_crypto_op *op = done[i];
			struct rte_mbuf *m = op->sym->m_src;
			struct opmeta *meta = rte_crypto_op_ctod_offset(op, struct opmeta *, META_OFFSET);
			struct fwd_sa *sa = meta->sa;
			struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *), *in;
			unsigned hl = (ip->version_ihl & 0x0f) * 4u, tot = rte_be_to_cpu_16(ip->total_length);
			uint32_t seq32; uint8_t padlen, nxt;
			const uint8_t *tr;
			const struct fwd_route *rt;
			const struct fwd_sp *sp;
			struct key4 key;

			if (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
				DROPLOG("auth spi=0x%08x seq=%u", rte_be_to_cpu_32(sa->spi), rte_be_to_cpu_32(*(uint32_t *)((uint8_t *)ip + hl + 4)));
				rte_pktmbuf_free(m); G.st.drop_auth++; rte_crypto_op_free(op); continue;
			}
			rte_crypto_op_free(op);
			memcpy(&seq32, (const uint8_t *)ip + hl + 4, 4); seq32 = rte_be_to_cpu_32(seq32);
			if (!replay_ok(sa, seq32)) {                       /* dup within one burst */
				DROPLOG("replay(post) spi=0x%08x seq=%u top=%lu", rte_be_to_cpu_32(sa->spi), seq32, sa->rp_top);
				rte_pktmbuf_free(m); G.st.drop_replay++; continue;
			}
			replay_update(sa, seq32);
			/* trailer: ... pad | padlen | nexthdr | ICV */
			tr = (const uint8_t *)ip + tot - ICV_LEN;
			padlen = tr[-2]; nxt = tr[-1];
			if (nxt != IPPROTO_IPIP || tot < hl + ESP_HLEN + ESP_IV_LEN + padlen + 2u + ICV_LEN + sizeof(struct rte_ipv4_hdr)) {
				rte_pktmbuf_free(m); G.st.drop_bad_esp++; continue;
			}
			rte_pktmbuf_trim(m, ICV_LEN + padlen + 2u);
			rte_pktmbuf_adj(m, hl + ESP_HLEN + ESP_IV_LEN);
			if (!(in = ip_check(m))) { rte_pktmbuf_free(m); G.st.drop_bad_ip++; continue; }
			/* inbound policy: the inner packet must match a PROTECT policy for THIS SA's tunnel */
			fill_key(&key, in, m);
			sp = spd_lookup(G.acl_in, &key);
			if (!sp || sp->sp.action != R2DP_ACT_PROTECT ||
			    memcmp(sp->sp.tun_src.addr, &sa->src, 4) != 0 || memcmp(sp->sp.tun_dst.addr, &sa->dst, 4) != 0) {
				rte_pktmbuf_free(m); G.st.drop_policy++; continue;
			}
			if (in->time_to_live <= 1) { rte_pktmbuf_free(m); G.st.drop_ttl++; continue; }
			if (!(rt = route_lookup(in->dst_addr))) { rte_pktmbuf_free(m); G.st.drop_no_route++; continue; }
			ip_fixup_ttl(in);
			sa->pkts++; sa->bytes += m->pkt_len; G.st.esp_in++;
			tx_queue(rt, m);
		}
	}
	(void)seqs;
}

/* ------------------------------------------------------------- init / main */
static void dump_stats(void)
{
	const struct fwd_stats *s = &G.st;
	printf("stats: rx_black=%lu rx_red=%lu tx_black=%lu tx_red=%lu esp_out=%lu esp_in=%lu bypass=%lu discard=%lu "
	       "exc_in=%lu exc_out=%lu\n",
	       s->rx[0], s->rx[1], s->tx[0], s->tx[1], s->esp_out, s->esp_in, s->bypass, s->discard,
	       s->exc_in, s->exc_out);
	printf("drops: not_us=%lu non_ip=%lu bad_ip=%lu ttl=%lu no_route=%lu no_sa=%lu no_sp_sa=%lu auth=%lu replay=%lu "
	       "bad_esp=%lu policy=%lu local=%lu too_big=%lu seq=%lu nobuf=%lu crypto=%lu\n",
	       s->drop_not_us, s->drop_non_ip, s->drop_bad_ip, s->drop_ttl, s->drop_no_route, s->drop_no_sa,
	       s->drop_no_sp_sa, s->drop_auth, s->drop_replay, s->drop_bad_esp, s->drop_policy, s->drop_local,
	       s->drop_too_big, s->drop_seq, s->drop_nobuf, s->drop_crypto);
	fflush(stdout);
}

static void on_sig(int s) { if (s == SIGUSR1) g_dump = 1; else g_stop = 1; }

static int port_init(uint16_t port)
{
	struct rte_eth_conf conf;
	memset(&conf, 0, sizeof(conf));
	if (rte_eth_dev_configure(port, 1, 1, &conf) < 0) return -1;
	if (rte_eth_rx_queue_setup(port, 0, 512, SOCKET_ID_ANY, NULL, G.pkt_pool) < 0) return -1;
	if (rte_eth_tx_queue_setup(port, 0, 512, SOCKET_ID_ANY, NULL) < 0) return -1;
	if (rte_eth_dev_start(port) < 0) return -1;
	rte_eth_promiscuous_enable(port);
	return rte_eth_macaddr_get(port, &G.mac[port]);
}

static int crypto_init(void)
{
	struct rte_cryptodev_config cc;
	struct rte_cryptodev_qp_conf qc;
	uint32_t sz;
	int sock;

	if (rte_cryptodev_count() <= G.cdev) { fprintf(stderr, "fwd: no crypto device (add --vdev crypto_openssl0)\n"); return -1; }
	sock = rte_cryptodev_socket_id(G.cdev);
	memset(&cc, 0, sizeof(cc)); cc.socket_id = sock; cc.nb_queue_pairs = 1;
	if (rte_cryptodev_configure(G.cdev, &cc) < 0) return -1;
	sz = rte_cryptodev_sym_get_private_session_size(G.cdev);
	G.sess_pool = rte_cryptodev_sym_session_pool_create("sess", 256, sz, 0, 0, sock);
	G.op_pool = rte_crypto_op_pool_create("ops", RTE_CRYPTO_OP_TYPE_SYMMETRIC, 4096, 128, OP_PRIV, sock);
	if (!G.sess_pool || !G.op_pool) return -1;
	memset(&qc, 0, sizeof(qc)); qc.nb_descriptors = 2048; qc.mp_session = G.sess_pool;
	if (rte_cryptodev_queue_pair_setup(G.cdev, 0, &qc, sock) < 0) return -1;
	return rte_cryptodev_start(G.cdev);
}

static void usage(void)
{
	fprintf(stderr, "usage: r2dp-fwd [EAL opts] -- --sock PATH --local IPV4 [--black N] [--red N]\n"
	                "                --route CIDR,black|red,MAC ... [--idle-us N] [-v]\n");
}

int main(int argc, char **argv)
{
	static const struct option lo[] = {
		{"sock", 1, 0, 's'}, {"local", 1, 0, 'l'}, {"route", 1, 0, 'r'}, {"idle-us", 1, 0, 'i'},
		{"verbose", 0, 0, 'v'}, {0, 0, 0, 0} };
	struct r2dp_cp_hooks hooks = { .sa_set = hook_sa_set, .sa_del = hook_sa_del,
	                               .sp_set = hook_sp_set, .sp_del = hook_sp_del };
	struct r2dp_cp_caps caps;
	struct r2dp_cp_opts opts = { .name = "r2dp-fwd" };
	struct rte_lpm_config lc = { .max_rules = 256, .number_tbl8s = 256 };
	struct rte_hash_parameters hp;
	const char *sock = NULL, *routes[MAX_RT]; int nr = 0;
	struct r2dp_srv *srv; struct r2dp_cp *cp;
	struct in_addr la;
	int ret, c;
	unsigned iter = 0;

	if ((ret = rte_eal_init(argc, argv)) < 0) { fprintf(stderr, "fwd: EAL init failed\n"); return 1; }
	argc -= ret; argv += ret; optind = 1;
	G.idle_us = 50; G.cdev = 0;
	while ((c = getopt_long(argc, argv, "v", lo, NULL)) != -1) {
		switch (c) {
		case 's': sock = optarg; break;
		case 'l': if (inet_pton(AF_INET, optarg, &la) != 1) { usage(); return 2; } G.local_ip = la.s_addr; break;
		case 'r': if (nr < MAX_RT) routes[nr++] = optarg; break;
		case 'i': G.idle_us = atoi(optarg); break;
		case 'v': G.verbose = opts.verbose = 1; break;
		default: usage(); return 2;
		}
	}
	if (!sock || !G.local_ip) { usage(); return 2; }
	if (rte_eth_dev_count_avail() < 2) { fprintf(stderr, "fwd: need two ports (black=0, red=1)\n"); return 1; }

	G.pkt_pool = rte_pktmbuf_pool_create("pkts", 8191, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	if (!G.pkt_pool) { fprintf(stderr, "fwd: mbuf pool: %s\n", rte_strerror(rte_errno)); return 1; }
	if (port_init(PORT_BLACK) < 0 || port_init(PORT_RED) < 0) { fprintf(stderr, "fwd: port init failed\n"); return 1; }
	if (rte_eth_dev_count_avail() >= 3) {
		if (port_init(PORT_TAP) < 0) { fprintf(stderr, "fwd: exception port init failed\n"); return 1; }
		/* The kernel must answer ARP with the MAC that our ESP traffic is addressed to. */
		if (rte_eth_dev_default_mac_addr_set(PORT_TAP, &G.mac[PORT_BLACK]) < 0) {
			fprintf(stderr, "fwd: cannot give the exception port the black MAC; start the vdev with mac=<black mac>\n");
			return 1;
		}
		G.mac[PORT_TAP] = G.mac[PORT_BLACK];
		G.has_tap = 1;
	}
	if (crypto_init() < 0) return 1;
	memset(&hp, 0, sizeof(hp));
	hp.name = "sad"; hp.entries = SAD_ENTRIES; hp.key_len = sizeof(struct hkey);
	hp.hash_func = rte_jhash; hp.socket_id = (int)rte_socket_id();
	if (!(G.sad = rte_hash_create(&hp))) { fprintf(stderr, "fwd: SAD: %s\n", rte_strerror(rte_errno)); return 1; }
	if (!(G.lpm = rte_lpm_create("rt", SOCKET_ID_ANY, &lc))) { fprintf(stderr, "fwd: LPM: %s\n", rte_strerror(rte_errno)); return 1; }
	for (int i = 0; i < nr; i++) if (add_route(routes[i]) < 0) { fprintf(stderr, "fwd: bad --route %s\n", routes[i]); return 2; }

	memset(&caps, 0, sizeof(caps));          /* M1: no ESN/NAT-T/IPv6/expiry */
	caps.enc_caps[R2DP_ENCR_AES_GCM_16 >> 5] |= 1u << (R2DP_ENCR_AES_GCM_16 & 31);
	caps.integ_caps[0] |= 1u;                /* NONE (AEAD) */
	if (!(cp = r2dp_cp_new(&hooks, &caps, &opts))) return 1;
	if (!(srv = r2dp_srv_new(sock))) { perror("fwd: control socket"); return 1; }
	signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGUSR1, on_sig); signal(SIGPIPE, SIG_IGN);
	fprintf(stderr, "fwd: exception path %s\n", G.has_tap ? "enabled (port 2)" : "disabled (no third port)");
	fprintf(stderr, "fwd: ready (black %02x:%02x:%02x:%02x:%02x:%02x red %02x:%02x:%02x:%02x:%02x:%02x)\n",
	        G.mac[0].addr_bytes[0], G.mac[0].addr_bytes[1], G.mac[0].addr_bytes[2], G.mac[0].addr_bytes[3],
	        G.mac[0].addr_bytes[4], G.mac[0].addr_bytes[5], G.mac[1].addr_bytes[0], G.mac[1].addr_bytes[1],
	        G.mac[1].addr_bytes[2], G.mac[1].addr_bytes[3], G.mac[1].addr_bytes[4], G.mac[1].addr_bytes[5]);

	while (!g_stop) {
		struct rte_mbuf *pk[BURST];
		unsigned nb, nr2;

		nr2 = rte_eth_rx_burst(PORT_RED, 0, pk, BURST);
		if (nr2) handle_red(pk, nr2);
		nb = rte_eth_rx_burst(PORT_BLACK, 0, pk, BURST);
		if (nb) handle_black(pk, nb);
		if (G.has_tap) {
			unsigned nk = rte_eth_rx_burst(PORT_TAP, 0, pk, BURST);
			for (unsigned i = 0; i < nk; i++) { G.st.rx[PORT_TAP]++; G.st.exc_out++; tx_raw(PORT_BLACK, pk[i]); }
			nb += nk;
		}
		tx_flush();
		if (!nr2 && !nb) {
			r2dp_srv_poll(srv, cp, 0);
			if (G.idle_us) rte_delay_us_sleep(G.idle_us);
		} else if ((++iter & 63) == 0) {
			r2dp_srv_poll(srv, cp, 0);
		}
		if (g_dump) { g_dump = 0; dump_stats(); }
	}
	dump_stats();
	r2dp_srv_free(srv); r2dp_cp_free(cp);
	rte_eal_cleanup();
	return 0;
}

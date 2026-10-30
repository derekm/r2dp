/*
 * r2dpctl: minimal control client for the r2dp forwarder.
 *
 * Speaks the r2dp control protocol to a live r2dp-fwd over its unix
 * SOCK_SEQPACKET socket and prints the forwarder's view of its SAD (and
 * optionally SPD).  The exit gate requires "r2dpctl dump matches SAD": the
 * source of truth is the forwarder's in-process SAD, and this tool reads it
 * back over the wire via R2DP_SA_DUMP / R2DP_SP_DUMP.
 *
 * Usage:
 *   r2dpctl [socket] dump          # all SAs, one per line (keys withheld)
 *   r2dpctl [socket] dump-sa       # same as dump
 *   r2dpctl [socket] dump-sp       # all policies
 *   r2dpctl [socket] count         # number of live SAs (0 if empty; 255 if)
 *   r2dpctl [socket] hello         # protocol version, features, caps
 *
 * Write commands (protocol v2; arguments are key=value):
 *   r2dpctl [socket] sa-add dir=in|out spi=0x1001 src=A dst=B
 *           enc=aes-gcm-16|aes-gcm-12|aes-gcm-8|aes-cbc|aes-ctr|null|NUM
 *           [integ=none|sha1|sha256|sha384|sha512|NUM] key=HEX [authkey=HEX]
 *           [reqid=N] [wsize=N (default 64, 0 = no anti-replay)] [mode=tunnel|transport] [natt=SPORT:DPORT]
 *   r2dpctl [socket] sa-del spi=0x1001 dst=B
 *   r2dpctl [socket] sp-add dir=in|out|fwd action=protect|discard|bypass
 *           src=NET/LEN dst=NET/LEN [proto=any|tcp|udp|icmp|NUM]
 *           [sport=N] [dport=N] [tsrc=A tdst=B] [reqid=N] [slid=N] [update]
 *   r2dpctl [socket] sp-del slid=N
 *   r2dpctl [socket] sp-del dir=.. src=NET/LEN dst=NET/LEN [proto=..]
 * Exit status: 0 ok, 1 the forwarder refused (errno printed), 2 usage.
 *
 * socket defaults to $R2DP_SOCK else /var/run/r2dp.sock.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "r2dp/client.h"

static const char *g_sock = NULL;

/* Send a dump request and print every reply until the last (MORE unset).
 * Return the number of entries, or a negative errno. */
static int
dump_loop(int fd, uint16_t type, int print)
{
	uint32_t seq = 0x444d5053;   /* 'DMPS' */
	int n = 0;
	int r = r2dp_send(fd, type, seq, 0, 0, NULL, 0, NULL, 0);
	if (r < 0)
		return r;

	for (;;) {
		struct r2dp_msg m;
		r = r2dp_recv(fd, &m);
		if (r < 0)
			return r;
		if (m.h.seq != seq || m.h.type != type)
			continue;   /* not our completion */
		if (m.h.status)      /* ENOENT => empty dump */
			return m.h.status == ENOENT ? 0 : -(int)m.h.status;
		n++;
		if (print) {
			if (type == R2DP_SA_DUMP) {
				const struct r2dp_sa *sa = r2dp_msg_sa(&m);
				char src[64] = "?", dst[64] = "?";
				if (sa->src.family == R2DP_AF_INET4)
					inet_ntop(AF_INET, sa->src.addr, src, sizeof(src));
				if (sa->dst.family == R2DP_AF_INET4)
					inet_ntop(AF_INET, sa->dst.addr, dst, sizeof(dst));
				uint32_t spi = ntohl(sa->spi);
				printf("SA spi=0x%08x dir=%u proto=%u mode=%u enc=%u "
				    "integ=%u src=%s dst=%s enckeylen=%u%s\n",
				    spi, sa->dir, sa->proto, sa->mode, sa->enc,
				    sa->integ, src, dst, sa->enckeylen,
				    (m.h.flags & R2DP_HF_MORE) ? " [more]" : "");
			} else {
				const struct r2dp_sp *sp = r2dp_msg_sp(&m);
				char s[64] = "?", d[64] = "?";
				if (sp->sel_src.family == R2DP_AF_INET4)
					inet_ntop(AF_INET, sp->sel_src.addr, s, sizeof(s));
				if (sp->sel_dst.family == R2DP_AF_INET4)
					inet_ntop(AF_INET, sp->sel_dst.addr, d, sizeof(d));
				char ts[64] = "?", td[64] = "?";
				if (sp->tun_src.family == R2DP_AF_INET4)
					inet_ntop(AF_INET, sp->tun_src.addr, ts, sizeof(ts));
				if (sp->tun_dst.family == R2DP_AF_INET4)
					inet_ntop(AF_INET, sp->tun_dst.addr, td, sizeof(td));
				printf("SP dir=%u action=%u slid=%u %s/%u:%u->%s/%u:%u proto=%u mode=%u tun=%s->%s reqid=%u\n",
				    sp->dir, sp->action, sp->slid,
				    s, sp->pref_src, ntohs(sp->sel_src.port),
				    d, sp->pref_dst, ntohs(sp->sel_dst.port),
				    sp->ul_proto, sp->mode, ts, td, sp->reqid);
			}
		}
		if (!(m.h.flags & R2DP_HF_MORE))
			return n;
	}
}

/* ---- write commands --------------------------------------------------- */

static const char *
kv(int argc, char **argv, const char *k)
{
	size_t n = strlen(k);
	for (int i = 0; i < argc; i++)
		if (!strncmp(argv[i], k, n) &&
		    (argv[i][n] == '=' || argv[i][n] == 0))
			return argv[i][n] == '=' ? argv[i] + n + 1 : "";
	return NULL;
}

static int
usage(const char *why)
{
	fprintf(stderr, "r2dpctl: %s (see the header of tools/r2dpctl.c)\n", why);
	return 2;
}

static int
parse_u32(const char *s, uint32_t *v)
{
	char *e;
	unsigned long x;
	if (!s || !*s) return -1;
	errno = 0;
	x = strtoul(s, &e, 0);
	if (errno || *e || x > 0xffffffffUL) return -1;
	*v = (uint32_t)x;
	return 0;
}

static int
parse_v4(const char *s, struct r2dp_addr *a, uint8_t *pref)
{
	char buf[64];
	const char *sl;
	uint32_t p = 32;

	if (!s || strlen(s) >= sizeof(buf)) return -1;
	strcpy(buf, s);
	sl = strchr(buf, '/');
	if (sl) {
		buf[sl - buf] = 0;
		if (!pref || parse_u32(sl + 1, &p) || p > 32) return -1;
	}
	memset(a, 0, sizeof(*a));
	if (inet_pton(AF_INET, buf, a->addr) != 1) return -1;
	a->family = R2DP_AF_INET4;
	if (pref) *pref = (uint8_t)p;
	return 0;
}

static int
parse_dir(const char *s, uint8_t *d)
{
	if (!s) return -1;
	if (!strcmp(s, "in")) *d = R2DP_DIR_IN;
	else if (!strcmp(s, "out")) *d = R2DP_DIR_OUT;
	else if (!strcmp(s, "fwd")) *d = R2DP_DIR_FWD;
	else return -1;
	return 0;
}

static int
parse_name(const char *s, const char *const names[], const int vals[], int *v)
{
	uint32_t n;
	for (int i = 0; names[i]; i++)
		if (!strcmp(s, names[i])) { *v = vals[i]; return 0; }
	if (parse_u32(s, &n) || n > 255) return -1;
	*v = (int)n;
	return 0;
}

static int
parse_hex(const char *s, uint8_t *out, size_t max)
{
	size_t n = s ? strlen(s) : 0;
	if (!n || n % 2 || n / 2 > max) return -1;
	for (size_t i = 0; i < n / 2; i++) {
		unsigned b;
		if (sscanf(s + 2 * i, "%2x", &b) != 1) return -1;
		out[i] = (uint8_t)b;
	}
	return (int)(n / 2);
}

/* Send one request and wait for its completion; 0 or -errno. */
static int
request(int fd, uint16_t type, uint32_t flags, const void *body, size_t blen,
    const void *tail, size_t tlen)
{
	static uint32_t seq = 0x57525430;   /* 'WRT0' */
	struct r2dp_msg m;
	int r;

	seq++;
	r = r2dp_send(fd, type, seq, 0, flags, body, blen, tail, tlen);
	if (r < 0)
		return r;
	for (;;) {
		r = r2dp_recv(fd, &m);
		if (r < 0)
			return r;
		if (m.h.seq == seq && m.h.type == type) {
			/* errno-style; tolerate a forwarder that sent -errno */
			int st = (int)m.h.status;
			return st < 0 ? st : -st;
		}
	}
}

static int
done(const char *what, int r)
{
	if (r < 0) {
		fprintf(stderr, "r2dpctl: %s: %s\n", what, strerror(-r));
		return 1;
	}
	printf("%s: ok\n", what);
	return 0;
}

static int
cmd_sa(int fd, int add, int argc, char **argv)
{
	static const char *const encn[] = { "aes-gcm-16", "aes-gcm-12",
	    "aes-gcm-8", "aes-cbc", "aes-ctr", "aes-ccm-16", "null",
	    "chacha20-poly1305", NULL };
	static const int encv[] = { R2DP_ENCR_AES_GCM_16, R2DP_ENCR_AES_GCM_12,
	    R2DP_ENCR_AES_GCM_8, R2DP_ENCR_AES_CBC, R2DP_ENCR_AES_CTR,
	    R2DP_ENCR_AES_CCM_16, R2DP_ENCR_NULL,
	    R2DP_ENCR_CHACHA20_POLY1305 };
	static const char *const intn[] = { "none", "sha1", "sha256", "sha384",
	    "sha512", NULL };
	static const int intv[] = { R2DP_INTEG_NONE, R2DP_INTEG_HMAC_SHA1_96,
	    R2DP_INTEG_HMAC_SHA2_256_128, R2DP_INTEG_HMAC_SHA2_384_192,
	    R2DP_INTEG_HMAC_SHA2_512_256 };
	struct r2dp_sa sa;
	uint8_t keys[2 * 64];
	uint32_t v;
	int ek = 0, ak = 0, e;
	const char *s;

	memset(&sa, 0, sizeof(sa));
	sa.proto = R2DP_PROTO_ESP;
	sa.mode = R2DP_MODE_TUNNEL;
	sa.wsize = 64;                 /* iked's default; wsize=0 turns it off */
	if (parse_u32(kv(argc, argv, "spi"), &v) || v < 256)
		return usage("spi=N (>= 256) required");
	sa.spi = htonl(v);
	if (parse_v4(kv(argc, argv, "dst"), &sa.dst, NULL))
		return usage("dst=IPv4 required");
	if (!add)
		return done("sa-del", request(fd, R2DP_SA_DEL, R2DP_HF_NOKEYS,
		    &sa, sizeof(sa), NULL, 0));

	if (parse_dir(kv(argc, argv, "dir"), &sa.dir) || sa.dir == R2DP_DIR_FWD)
		return usage("dir=in|out required (protocol v2)");
	if (parse_v4(kv(argc, argv, "src"), &sa.src, NULL))
		return usage("src=IPv4 required");
	if (!(s = kv(argc, argv, "enc")) || parse_name(s, encn, encv, &e))
		return usage("enc=... required");
	sa.enc = (uint8_t)e;
	e = R2DP_INTEG_NONE;
	if ((s = kv(argc, argv, "integ")) && parse_name(s, intn, intv, &e))
		return usage("bad integ=");
	sa.integ = (uint8_t)e;
	if ((s = kv(argc, argv, "mode"))) {
		if (!strcmp(s, "tunnel")) sa.mode = R2DP_MODE_TUNNEL;
		else if (!strcmp(s, "transport")) sa.mode = R2DP_MODE_TRANSPORT;
		else return usage("mode=tunnel|transport");
	}
	if ((s = kv(argc, argv, "reqid")) && parse_u32(s, &sa.reqid))
		return usage("bad reqid=");
	if ((s = kv(argc, argv, "wsize"))) {
		if (parse_u32(s, &v) || v > 255) return usage("wsize=0..255");
		sa.wsize = (uint8_t)v;
	}
	if ((s = kv(argc, argv, "natt"))) {
		unsigned sp, dp;
		if (sscanf(s, "%u:%u", &sp, &dp) != 2 || sp > 65535 || dp > 65535)
			return usage("natt=SPORT:DPORT");
		sa.natt_type = R2DP_NATT_ESPINUDP;
		sa.natt_sport = htons((uint16_t)sp);
		sa.natt_dport = htons((uint16_t)dp);
	}
	if ((ek = parse_hex(kv(argc, argv, "key"), keys, 64)) < 0)
		return usage("key=HEX required (incl. salt/nonce, max 64 bytes)");
	if ((s = kv(argc, argv, "authkey")) &&
	    (ak = parse_hex(s, keys + ek, 64)) < 0)
		return usage("bad authkey=HEX");
	sa.enckeylen = (uint16_t)ek;
	sa.authkeylen = (uint16_t)ak;
	sa.natoa_src.family = sa.natoa_dst.family = R2DP_AF_UNSET;
	return done("sa-add", request(fd, R2DP_SA_ADD, 0, &sa, sizeof(sa),
	    keys, (size_t)(ek + ak)));
}

static int
cmd_sp(int fd, int add, int argc, char **argv)
{
	static const char *const actn[] = { "protect", "discard", "bypass", NULL };
	static const int actv[] = { R2DP_ACT_PROTECT, R2DP_ACT_DISCARD,
	    R2DP_ACT_BYPASS };
	static const char *const prn[] = { "any", "tcp", "udp", "icmp", "sctp",
	    NULL };
	static const int prv[] = { R2DP_PROTO_ANY, 6, 17, 1, 132 };
	struct r2dp_sp sp;
	const char *s;
	uint32_t v;
	int e;

	memset(&sp, 0, sizeof(sp));
	sp.ul_proto = R2DP_PROTO_ANY;
	sp.mode = R2DP_MODE_TUNNEL;
	if ((s = kv(argc, argv, "slid")) && parse_u32(s, &sp.slid))
		return usage("bad slid=");
	if (!add && sp.slid)
		return done("sp-del", request(fd, R2DP_SP_DEL, 0, &sp,
		    sizeof(sp), NULL, 0));
	if (parse_dir(kv(argc, argv, "dir"), &sp.dir))
		return usage("dir=in|out|fwd required");
	if (parse_v4(kv(argc, argv, "src"), &sp.sel_src, &sp.pref_src) ||
	    parse_v4(kv(argc, argv, "dst"), &sp.sel_dst, &sp.pref_dst))
		return usage("src=NET/LEN dst=NET/LEN required");
	if ((s = kv(argc, argv, "proto"))) {
		if (parse_name(s, prn, prv, &e)) return usage("bad proto=");
		sp.ul_proto = (uint8_t)e;
	}
	if ((s = kv(argc, argv, "sport"))) {
		if (parse_u32(s, &v) || v > 65535) return usage("bad sport=");
		sp.sel_src.port = htons((uint16_t)v);
	}
	if ((s = kv(argc, argv, "dport"))) {
		if (parse_u32(s, &v) || v > 65535) return usage("bad dport=");
		sp.sel_dst.port = htons((uint16_t)v);
	}
	if (!add)
		return done("sp-del", request(fd, R2DP_SP_DEL, 0, &sp,
		    sizeof(sp), NULL, 0));
	if (!(s = kv(argc, argv, "action")) || parse_name(s, actn, actv, &e) ||
	    e < R2DP_ACT_PROTECT || e > R2DP_ACT_BYPASS)
		return usage("action=protect|discard|bypass required");
	sp.action = (uint8_t)e;
	if ((s = kv(argc, argv, "reqid")) && parse_u32(s, &sp.reqid))
		return usage("bad reqid=");
	if (kv(argc, argv, "tsrc") || kv(argc, argv, "tdst")) {
		if (parse_v4(kv(argc, argv, "tsrc"), &sp.tun_src, NULL) ||
		    parse_v4(kv(argc, argv, "tdst"), &sp.tun_dst, NULL))
			return usage("tsrc=IPv4 tdst=IPv4 go together");
	} else if (sp.action == R2DP_ACT_PROTECT)
		return usage("protect needs tsrc= and tdst= (tunnel endpoints)");
	if (kv(argc, argv, "update"))
		sp.flags |= R2DP_SPF_UPDATE;
	return done("sp-add", request(fd, R2DP_SP_ADD, 0, &sp, sizeof(sp),
	    NULL, 0));
}

static int
is_cmd(const char *s)
{
	static const char *const cmds[] = { "dump", "dump-sa", "dump-sp",
	    "count", "hello", "sa-add", "sa-del", "sp-add", "sp-del", NULL };
	for (int i = 0; cmds[i]; i++)
		if (!strcmp(s, cmds[i]))
			return 1;
	return 0;
}

int
main(int argc, char **argv)
{
	const char *cmd = "dump";
	int ai = 1;          /* first argument after the command */

	/* r2dpctl [socket] [command [key=value...]] */
	if (argc >= 2 && !is_cmd(argv[1]) && argv[1][0] != '-') {
		g_sock = argv[1];
		ai = 2;
	}
	if (argc > ai && is_cmd(argv[ai]))
		cmd = argv[ai++];
	else if (argc > ai && argv[ai][0] != '-') {
		fprintf(stderr, "r2dpctl: unknown cmd '%s'\n", argv[ai]);
		return 2;
	}

	if (!g_sock)
		g_sock = getenv("R2DP_SOCK");
	if (!g_sock)
		g_sock = "/var/run/r2dp.sock";

	int fd = r2dp_connect(g_sock);
	if (fd < 0) {
		fprintf(stderr, "r2dpctl: connect %s: %s\n",
		    g_sock, strerror(-fd));
		return 1;
	}
	struct r2dp_hello_ack ack;
	int hr = r2dp_hello(fd, R2DP_ROLE_CTL, &ack);
	if (hr < 0) {
		fprintf(stderr, "r2dpctl: hello: %s\n", strerror(-hr));
		close(fd);
		return 1;
	}
	if (!strcmp(cmd, "hello")) {
		printf("hello: ok version=%u epoch=0x%llx max_msg=%u features=0x%x\n",
		    R2DP_VERSION, (unsigned long long)ack.epoch, ack.max_msg,
		    ack.features);
		printf("enc_caps:");
		for (unsigned i = 0; i < 256; i++)
			if (r2dp_cap(ack.enc_caps, i)) printf(" %u", i);
		printf("\ninteg_caps:");
		for (unsigned i = 0; i < 256; i++)
			if (r2dp_cap(ack.integ_caps, i)) printf(" %u", i);
		printf("\n");
		close(fd);
		return 0;
	}
	if (!strncmp(cmd, "sa-", 3) || !strncmp(cmd, "sp-", 3)) {
		int add = !strcmp(cmd + 3, "add");
		int r = cmd[1] == 'a' ?
		    cmd_sa(fd, add, argc - ai, argv + ai) :
		    cmd_sp(fd, add, argc - ai, argv + ai);
		close(fd);
		return r;
	}

	if (!strcmp(cmd, "dump") || !strcmp(cmd, "dump-sa")) {
		int n = dump_loop(fd, R2DP_SA_DUMP, 1);
		if (n < 0) { fprintf(stderr, "r2dpctl: SA dump: %s\n",
		    strerror(-n)); close(fd); return 1; }
		fprintf(stderr, "r2dpctl: %d SA(s)\n", n);
	} else if (!strcmp(cmd, "dump-sp")) {
		int n = dump_loop(fd, R2DP_SP_DUMP, 1);
		if (n < 0) { fprintf(stderr, "r2dpctl: SP dump: %s\n",
		    strerror(-n)); close(fd); return 1; }
		fprintf(stderr, "r2dpctl: %d SP(s)\n", n);
	} else if (!strcmp(cmd, "count")) {
		int n = dump_loop(fd, R2DP_SA_DUMP, 0);
		if (n < 0) { fprintf(stderr, "r2dpctl: count: %s\n",
		    strerror(-n)); close(fd); return 1; }
		printf("%d\n", n);
	} else {
		fprintf(stderr, "r2dpctl: unknown cmd '%s'\n", cmd);
		close(fd);
		return 2;
	}
	close(fd);
	return 0;
}

/*
 * r2dpctl: talk to any r2dp forwarder (mock or DPDK) from the shell.
 *
 *   r2dpctl [-s sock] hello
 *   r2dpctl [-s sock] sa-add --spi N --src A --dst B --key HEX [--enc gcm8|gcm12|gcm16]
 *                            [--mode tunnel|transport] [--esn] [--reqid N] [--update]
 *   r2dpctl [-s sock] sa-del --spi N --dst B
 *   r2dpctl [-s sock] sp-add --dir in|out|fwd --src CIDR --dst CIDR
 *                            --action protect|bypass|discard [--proto N] [--sport N] [--dport N]
 *                            [--tun-src A --tun-dst B] [--reqid N] [--update]
 *   r2dpctl [-s sock] sp-del --slid N
 *   r2dpctl [-s sock] sp-dump
 *
 * AEAD keys are HEX of cipher_key || 4-byte salt (RFC 4106), e.g. 20 bytes for AES-128-GCM.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "r2dp/client.h"

static int die(const char *m) { fprintf(stderr, "r2dpctl: %s\n", m); return 2; }

static int parse_addr(struct r2dp_addr *a, const char *s)
{
	memset(a, 0, sizeof(*a));
	if (inet_pton(AF_INET, s, a->addr) == 1) { a->family = R2DP_AF_INET4; return 0; }
	if (inet_pton(AF_INET6, s, a->addr) == 1) { a->family = R2DP_AF_INET6; return 0; }
	return -1;
}
static int parse_cidr(struct r2dp_addr *a, uint8_t *pref, const char *s)
{
	char buf[64], *sl;
	snprintf(buf, sizeof(buf), "%s", s);
	if ((sl = strchr(buf, '/'))) *sl++ = 0;
	if (parse_addr(a, buf)) return -1;
	*pref = sl ? (uint8_t)atoi(sl) : (a->family == R2DP_AF_INET4 ? 32 : 128);
	return 0;
}
static int parse_hex(uint8_t *out, size_t max, const char *s)
{
	size_t n = strlen(s);
	if (n % 2 || n / 2 > max) return -1;
	for (size_t i = 0; i < n / 2; i++) {
		unsigned v;
		if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
		out[i] = (uint8_t)v;
	}
	return (int)(n / 2);
}

static const char *errname(unsigned st) { return st ? strerror((int)st) : "ok"; }

static int xfer(int fd, uint16_t type, uint32_t flags, const void *b, size_t bl,
                const void *t, size_t tl, struct r2dp_msg *rep)
{
	int r = r2dp_send(fd, type, 1, 0, flags, b, bl, t, tl);
	if (r < 0) return r;
	return r2dp_recv(fd, rep);
}

static void print_sp(const struct r2dp_sp *sp)
{
	char s[64], d[64];
	inet_ntop(sp->sel_src.family == R2DP_AF_INET6 ? AF_INET6 : AF_INET, sp->sel_src.addr, s, sizeof(s));
	inet_ntop(sp->sel_dst.family == R2DP_AF_INET6 ? AF_INET6 : AF_INET, sp->sel_dst.addr, d, sizeof(d));
	printf("slid=%u dir=%u %s/%u -> %s/%u proto=%u action=%u mode=%u protos=0x%x\n", sp->slid, sp->dir,
	       s, sp->pref_src, d, sp->pref_dst, sp->ul_proto, sp->action, sp->mode, sp->protos);
}

int main(int argc, char **argv)
{
	const char *sock = NULL, *cmd;
	int fd, r, c;

	if (argc > 2 && !strcmp(argv[1], "-s")) { sock = argv[2]; argv += 2; argc -= 2; }
	if (argc < 2) return die("usage: r2dpctl [-s sock] hello|sa-add|sa-del|sp-add|sp-del|sp-dump ...");
	cmd = argv[1]; argv++; argc--;

	static struct option lo[] = {
		{"spi", 1, 0, 's'}, {"src", 1, 0, 'a'}, {"dst", 1, 0, 'b'}, {"key", 1, 0, 'k'},
		{"enc", 1, 0, 'e'}, {"mode", 1, 0, 'm'}, {"esn", 0, 0, 'E'}, {"reqid", 1, 0, 'r'},
		{"update", 0, 0, 'u'}, {"dir", 1, 0, 'd'}, {"action", 1, 0, 'A'}, {"proto", 1, 0, 'p'},
		{"sport", 1, 0, 'S'}, {"dport", 1, 0, 'D'}, {"tun-src", 1, 0, 't'}, {"tun-dst", 1, 0, 'T'},
		{"slid", 1, 0, 'l'}, {0, 0, 0, 0} };
	struct r2dp_sa sa; struct r2dp_sp sp; uint8_t key[R2DP_MAX_KEY]; int keylen = 0;
	uint32_t spi = 0, slid = 0; int upd = 0, have_src = 0, have_dst = 0, have_tuns = 0, have_tund = 0;
	const char *dirs = NULL, *acts = NULL;
	memset(&sa, 0, sizeof(sa)); memset(&sp, 0, sizeof(sp));
	sa.proto = R2DP_PROTO_ESP; sa.mode = R2DP_MODE_TUNNEL; sa.enc = R2DP_ENCR_AES_GCM_16; sa.wsize = 64;
	sp.ul_proto = R2DP_PROTO_ANY; sp.level = R2DP_LVL_REQUIRE; sp.protos = R2DP_SPP_ESP; sp.mode = R2DP_MODE_TUNNEL;
	optind = 1;
	while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
		switch (c) {
		case 's': spi = (uint32_t)strtoul(optarg, NULL, 0); break;
		case 'a':
			if (!strcmp(cmd, "sp-add")) {
				if (parse_cidr(&sp.sel_src, &sp.pref_src, optarg)) return die("bad --src");
			} else if (parse_addr(&sa.src, optarg)) {
				return die("bad --src");
			}
			have_src = 1; break;
		case 'b':
			if (!strcmp(cmd, "sp-add")) {
				if (parse_cidr(&sp.sel_dst, &sp.pref_dst, optarg)) return die("bad --dst");
			} else if (parse_addr(&sa.dst, optarg)) {
				return die("bad --dst");
			}
			have_dst = 1; break;
		case 'k': if ((keylen = parse_hex(key, sizeof(key), optarg)) < 0) return die("bad --key hex"); break;
		case 'e': sa.enc = !strcmp(optarg, "gcm8") ? R2DP_ENCR_AES_GCM_8 : !strcmp(optarg, "gcm12") ? R2DP_ENCR_AES_GCM_12
		               : !strcmp(optarg, "gcm16") ? R2DP_ENCR_AES_GCM_16 : 0; if (!sa.enc) return die("bad --enc"); break;
		case 'm': sa.mode = sp.mode = !strcmp(optarg, "transport") ? R2DP_MODE_TRANSPORT : R2DP_MODE_TUNNEL; break;
		case 'E': sa.saflags |= R2DP_SAF_ESN; break;
		case 'r': sa.reqid = sp.reqid = (uint32_t)atoi(optarg); break;
		case 'u': upd = 1; break;
		case 'd': dirs = optarg; break;
		case 'A': acts = optarg; break;
		case 'p': sp.ul_proto = (uint8_t)atoi(optarg); break;
		case 'S': sp.sel_src.port = htons((uint16_t)atoi(optarg)); break;
		case 'D': sp.sel_dst.port = htons((uint16_t)atoi(optarg)); break;
		case 't': if (parse_addr(&sp.tun_src, optarg)) return die("bad --tun-src"); have_tuns = 1; break;
		case 'T': if (parse_addr(&sp.tun_dst, optarg)) return die("bad --tun-dst"); have_tund = 1; break;
		case 'l': slid = (uint32_t)atoi(optarg); break;
		default: return die("bad option");
		}
	}
	if ((fd = r2dp_connect(sock)) < 0) { fprintf(stderr, "r2dpctl: connect: %s\n", strerror(-fd)); return 1; }
	struct r2dp_msg rep;

	if (!strcmp(cmd, "hello")) {
		struct r2dp_hello_ack ack;
		if ((r = r2dp_hello(fd, R2DP_ROLE_CTL, &ack)) < 0) { fprintf(stderr, "hello: %s\n", strerror(-r)); return 1; }
		printf("features=0x%x max_msg=%u epoch=%llu gcm16=%d\n", ack.features, ack.max_msg,
		       (unsigned long long)ack.epoch, r2dp_cap(ack.enc_caps, R2DP_ENCR_AES_GCM_16));
		return 0;
	}
	if (!strcmp(cmd, "sa-add")) {
		if (!spi || !have_src || !have_dst || keylen <= 0) return die("sa-add needs --spi --src --dst --key");
		sa.spi = htonl(spi); sa.enckeylen = (uint16_t)keylen;
		r = xfer(fd, R2DP_SA_ADD, 0, &sa, sizeof(sa), key, keylen, &rep);
	} else if (!strcmp(cmd, "sa-del")) {
		if (!spi || !have_dst) return die("sa-del needs --spi --dst");
		sa.spi = htonl(spi);
		r = xfer(fd, R2DP_SA_DEL, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, &rep);
	} else if (!strcmp(cmd, "sp-add")) {
		if (!dirs || !acts || !have_src || !have_dst) return die("sp-add needs --dir --src --dst --action");
		sp.dir = !strcmp(dirs, "in") ? R2DP_DIR_IN : !strcmp(dirs, "out") ? R2DP_DIR_OUT : R2DP_DIR_FWD;
		sp.action = !strcmp(acts, "protect") ? R2DP_ACT_PROTECT : !strcmp(acts, "discard") ? R2DP_ACT_DISCARD : R2DP_ACT_BYPASS;
		if (sp.action != R2DP_ACT_PROTECT) { sp.protos = 0; sp.mode = 0; }
		else if (sp.mode == R2DP_MODE_TUNNEL && (!have_tuns || !have_tund)) return die("tunnel policy needs --tun-src --tun-dst");
		if (upd) sp.flags |= R2DP_SPF_UPDATE;
		r = xfer(fd, R2DP_SP_ADD, 0, &sp, sizeof(sp), NULL, 0, &rep);
		if (r == 0 && rep.h.status == 0) printf("slid=%u\n", r2dp_msg_sp(&rep)->slid);
	} else if (!strcmp(cmd, "sp-del")) {
		if (!slid) return die("sp-del needs --slid");
		sp.slid = slid;
		r = xfer(fd, R2DP_SP_DEL, 0, &sp, sizeof(sp), NULL, 0, &rep);
	} else if (!strcmp(cmd, "sp-dump")) {
		r = r2dp_send(fd, R2DP_SP_DUMP, 1, 0, 0, &sp, sizeof(sp), NULL, 0);
		while (r == 0) {
			if ((r = r2dp_recv(fd, &rep)) < 0) break;
			if (rep.h.status) { fprintf(stderr, "sp-dump: %s\n", errname(rep.h.status)); return rep.h.status == ENOENT ? 0 : 1; }
			print_sp(r2dp_msg_sp(&rep));
			if (!(rep.h.flags & R2DP_HF_MORE)) break;
		}
		if (r < 0) { fprintf(stderr, "sp-dump: %s\n", strerror(-r)); return 1; }
		return 0;
	} else return die("unknown command");

	if (r < 0) { fprintf(stderr, "%s: %s\n", cmd, strerror(-r)); return 1; }
	if (rep.h.status) { fprintf(stderr, "%s: %s\n", cmd, errname(rep.h.status)); return 1; }
	printf("%s: ok\n", cmd);
	return 0;
}

/*
 * Contract test: drives racoon2's real rcpfk_* API (via shim/if_r2dp.c)
 * against r2dp-mockfwd, then inspects the mock over a raw r2dp connection
 * to prove the forwarder saw full selectors, ESN, NAT-T, and keys.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include "vmbuf.h"
#include "rc_type.h"
#include "if_pfkeyv2.h"
#include "r2dp/client.h"

extern uint32_t rc_spirange_min, rc_spirange_max;   /* defined by the backend; iked externs them too */

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* callback recorder */
static struct { int n_getspi, n_update, n_add, n_delete, n_get, n_spdadd, n_spddel2, n_spddump;
                uint32_t spi, slid, seq_last, reqid; uint8_t satype, samode, dir, pltype;
                struct sockaddr_storage dst; int dst_set; uint32_t seqs[8]; int nseq;
                int n_expire; uint8_t expired[4]; uint64_t exp_alloc; uint32_t exp_spi; uint8_t exp_satype, exp_samode;
                uint32_t exp_reqid; int exp_dst_ok; } rec;

static int on_getspi(struct rcpfk_msg *rc) { rec.n_getspi++; rec.spi = rc->spi; rec.seq_last = rc->seq;
	rec.satype = rc->satype; rec.samode = rc->samode; rec.reqid = rc->reqid;
	rec.seqs[rec.nseq++ & 7] = rc->seq;
	if (rc->sa_dst) { memcpy(&rec.dst, rc->sa_dst, sizeof(struct sockaddr_in)); rec.dst_set = 1; }
	return 0; }
static int on_update(struct rcpfk_msg *rc) { (void)rc; rec.n_update++; return 0; }
static int on_add(struct rcpfk_msg *rc) { (void)rc; rec.n_add++; return 0; }
static int on_delete(struct rcpfk_msg *rc) { (void)rc; rec.n_delete++; return 0; }
static int on_get(struct rcpfk_msg *rc) { (void)rc; rec.n_get++; return 0; }
static int on_spdadd(struct rcpfk_msg *rc) { rec.n_spdadd++; rec.slid = rc->slid; rec.dir = rc->dir;
	rec.pltype = rc->pltype; return 0; }
static int on_spddel2(struct rcpfk_msg *rc) { (void)rc; rec.n_spddel2++; return 0; }
static int on_expire(struct rcpfk_msg *rc)
{
	if (rec.n_expire < 4) rec.expired[rec.n_expire] = rc->expired;
	rec.n_expire++; rec.exp_alloc = rc->lft_current_alloc; rec.exp_spi = rc->spi;
	rec.exp_satype = rc->satype; rec.exp_samode = rc->samode; rec.exp_reqid = rc->reqid;
	rec.exp_dst_ok = rc->sa_dst && rc->sa_dst->sa_family == AF_INET;
	return 0;
}
static int on_spddump(struct rcpfk_msg *rc) { (void)rc; rec.n_spddump++; return 0; }

static struct rcpfk_cb cbs = { .cb_getspi = on_getspi, .cb_update = on_update, .cb_add = on_add,
	.cb_delete = on_delete, .cb_get = on_get, .cb_spdadd = on_spdadd,
	.cb_spddelete2 = on_spddel2, .cb_spddump = on_spddump, .cb_expire = on_expire };

static void sin4(struct sockaddr_in *s, const char *ip, int port)
{
	memset(s, 0, sizeof(*s)); s->sin_family = AF_INET; s->sin_port = htons(port);
	inet_pton(AF_INET, ip, &s->sin_addr);
}

static int wait1(struct rcpfk_msg *rc) { rc->flags |= PFK_FLAG_WAITREPLY; return rcpfk_handler(rc); }

int main(int argc, char **argv)
{
	char dir[] = "/tmp/r2dp-shim-XXXXXX", sock[128];
	struct rcpfk_msg rc;
	struct sockaddr_in src, dst, ssrc, sdst, natoa_s, natoa_d;
	uint8_t key[36], akey[1];
	pid_t mock;
	int raw, i;

	if (argc < 2) return 2;
	if (!mkdtemp(dir)) return 2;
	snprintf(sock, sizeof(sock), "%s/s", dir);
	setenv(R2DP_ENV_SOCK, sock, 1);
	setenv("R2DP_ROLE", "iked", 1);
	if ((mock = fork()) == 0) { execl(argv[1], argv[1], "-s", sock, "-K", "-L", (char *)NULL); _exit(127); }
	for (i = 0; i < 100; i++) { raw = r2dp_connect(sock); if (raw >= 0) break; usleep(20000); }
	CHECK(raw >= 0);

	memset(&rc, 0, sizeof(rc));
	CHECK(rcpfk_init(&rc, &cbs) == 0 && rc.so >= 0);

	/* capabilities drive supported_* */
	CHECK(rcpfk_supported_enc(RCT_ALG_AES_GCM) == 1);
	CHECK(rcpfk_supported_enc(RCT_ALG_RIJNDAEL_CBC) == 1);
	CHECK(rcpfk_supported_enc(RCT_ALG_DES_CBC_IV64) == 0);       /* no wire mapping */
	CHECK(rcpfk_supported_auth(RCT_ALG_HMAC_SHA2_256) == 1);
	CHECK(rcpfk_supported_auth(RCT_ALG_KPDK_MD5) == 0);

	sin4(&src, "192.0.2.1", 0); sin4(&dst, "192.0.2.2", 0);
	rc.sa_src = (struct sockaddr *)&src; rc.sa_dst = (struct sockaddr *)&dst;
	rc.satype = RCT_SATYPE_ESP; rc.samode = RCT_IPSM_TUNNEL; rc.reqid = 5; rc.seq = 7;
	rc_spirange_min = 0x2000; rc_spirange_max = 0x2fff;

	/* GETSPI: completion fires cb_getspi with SPI in range + addresses back */
	CHECK(rcpfk_send_getspi(&rc) == 0);
	CHECK(wait1(&rc) == 0);
	CHECK(rec.n_getspi == 1 && ntohl(rec.spi) >= 0x2000 && ntohl(rec.spi) <= 0x2fff);
	CHECK(rec.seq_last == 7 && rec.satype == RCT_SATYPE_ESP && rec.samode == RCT_IPSM_TUNNEL);
	CHECK(rec.reqid == 5 && rec.dst_set &&
	      ((struct sockaddr_in *)&rec.dst)->sin_addr.s_addr == dst.sin_addr.s_addr);

	/* UPDATE: AES-GCM-16 + ESN + NAT-T + NAT-OA + lifetimes + key */
	for (i = 0; i < (int)sizeof(key); i++) key[i] = (uint8_t)(0xc0 + i);
	akey[0] = 0;
	sin4(&natoa_s, "10.9.9.1", 0); sin4(&natoa_d, "10.9.9.2", 0);
	rc.spi = rec.spi; rc.seq = 8;
	rc.enctype = RCT_ALG_AES_GCM; rc.authtype = RCT_ALG_NON_AUTH;
	rc.enckey = (caddr_t)key; rc.enckeylen = sizeof(key); rc.authkey = (caddr_t)akey; rc.authkeylen = 0;
	rc.saflags = SADB_X_SAFLAGS_ESN; rc.wsize = 64;
	rc.natt_type = 2; rc.natt_sport = htons(4500); rc.natt_dport = htons(4500);
	rc.sa_natoa_src = (struct sockaddr *)&natoa_s; rc.sa_natoa_dst = (struct sockaddr *)&natoa_d;
	rc.lft_hard_time = 3600; rc.lft_soft_time = 3000;
	CHECK(rcpfk_send_update(&rc) == 0);
	CHECK(wait1(&rc) == 0 && rec.n_update == 1);

	/* what did the forwarder actually receive?  (raw view of the mock) */
	{
		struct r2dp_sa q; struct r2dp_msg rep; const struct r2dp_sa *sa;
		memset(&q, 0, sizeof(q));
		q.spi = rec.spi; q.proto = R2DP_PROTO_ESP; q.dst.family = R2DP_AF_INET4;
		memcpy(q.dst.addr, &dst.sin_addr, 4);
		CHECK(r2dp_send(raw, R2DP_SA_GET, 1, 0, R2DP_HF_NOKEYS, &q, sizeof(q), NULL, 0) == 0);
		CHECK(r2dp_recv(raw, &rep) == 0 && rep.h.status == 0);
		sa = r2dp_msg_sa(&rep);
		CHECK(sa->enc == R2DP_ENCR_AES_GCM_16 && sa->integ == R2DP_INTEG_NONE);
		CHECK(sa->proto == R2DP_PROTO_ESP && sa->mode == R2DP_MODE_TUNNEL);
		CHECK(sa->saflags & R2DP_SAF_ESN);                         /* ESN survived the shim */
		CHECK(sa->natt_type == R2DP_NATT_ESPINUDP && sa->natt_dport == htons(4500));
		CHECK(sa->natoa_src.family == R2DP_AF_INET4 && sa->natoa_dst.family == R2DP_AF_INET4);
		CHECK(sa->wsize == 64 && sa->reqid == 5 && sa->lft_hard_time == 3600 && sa->lft_soft_time == 3000);
		CHECK(sa->enckeylen == 36 && memcmp(r2dp_msg_enckey(&rep), key, 36) == 0);
	}

	/* SPD: selectors, ports, tunnel endpoints, bundle */
	sin4(&ssrc, "10.0.0.0", 0); sin4(&sdst, "10.0.1.0", 443);
	rc.sp_src = (struct sockaddr *)&ssrc; rc.sp_dst = (struct sockaddr *)&sdst;
	rc.pref_src = rc.pref_dst = 24; rc.ul_proto = 6; rc.dir = RCT_DIR_OUTBOUND;
	rc.pltype = RCT_ACT_AUTO_IPSEC; rc.satype = RCT_SATYPE_ESP; rc.samode = RCT_IPSM_TUNNEL;
	rc.ipsec_level = RCT_IPSL_REQUIRE; rc.reqid = 5; rc.seq = 9; rc.slid = 0;
	strcpy(rc.tag_name, "");
	CHECK(rcpfk_send_spdadd(&rc) == 0 && wait1(&rc) == 0);
	CHECK(rec.n_spdadd == 1 && rec.slid != 0 && rec.dir == RCT_DIR_OUTBOUND && rec.pltype == RCT_ACT_AUTO_IPSEC);
	{
		struct r2dp_sp q; struct r2dp_msg rep; const struct r2dp_sp *sp;
		memset(&q, 0, sizeof(q)); q.slid = rec.slid;
		CHECK(r2dp_send(raw, R2DP_SP_GET, 2, 0, 0, &q, sizeof(q), NULL, 0) == 0);
		CHECK(r2dp_recv(raw, &rep) == 0 && rep.h.status == 0);
		sp = r2dp_msg_sp(&rep);
		CHECK(sp->dir == R2DP_DIR_OUT && sp->action == R2DP_ACT_PROTECT && sp->mode == R2DP_MODE_TUNNEL);
		CHECK(sp->protos == R2DP_SPP_ESP && sp->ul_proto == 6 && sp->pref_src == 24 && sp->pref_dst == 24);
		CHECK(sp->sel_dst.port == htons(443) && sp->sel_src.family == R2DP_AF_INET4);
		CHECK(sp->tun_src.family == R2DP_AF_INET4 && sp->tun_dst.family == R2DP_AF_INET4);
		CHECK(memcmp(sp->tun_dst.addr, &dst.sin_addr, 4) == 0 && sp->reqid == 5);
	}

	/* same selector again => forwarder EEXIST surfaces as handler -1 / rc.eno */
	rc.seq = 10;
	CHECK(rcpfk_send_spdadd(&rc) == 0);
	CHECK(wait1(&rc) == -1 && rc.eno == EEXIST);
	rc.slid = rec.slid;

	/* dump with WAITREPLY consumes the stream */
	rc.seq = 11;
	CHECK(rcpfk_send_spddump(&rc) == 0 && wait1(&rc) == 0 && rec.n_spddump == 1);

	/* WAITREPLY picks *its* reply and routes the other through scratch */
	{
		struct rcpfk_msg b = rc; int before = rec.n_getspi;
		rc.satype = RCT_SATYPE_ESP; rc.samode = RCT_IPSM_TUNNEL; rc.slid = 0;
		rc.sa_src = (struct sockaddr *)&src; rc.sa_dst = (struct sockaddr *)&dst;
		rc.seq = 20; CHECK(rcpfk_send_getspi(&rc) == 0);
		rc.seq = 21; CHECK(rcpfk_send_getspi(&rc) == 0);
		(void)b;
		CHECK(wait1(&rc) == 0);                      /* waits for seq 21 */
		CHECK(rec.n_getspi == before + 2);           /* 20 via scratch, 21 via rc */
		CHECK(rec.seqs[(rec.nseq - 2) & 7] == 20 && rec.seqs[(rec.nseq - 1) & 7] == 21);
	}

	/* deletes */
	rc.slid = rec.slid; rc.seq = 30;
	CHECK(rcpfk_send_spddelete2(&rc) == 0 && wait1(&rc) == 0 && rec.n_spddel2 == 1);
	rc.seq = 31;
	CHECK(rcpfk_send_spddelete2(&rc) == 0 && wait1(&rc) == -1 && rc.eno == ENOENT);

	rc.spi = rec.spi; rc.seq = 32;
	CHECK(rcpfk_send_delete(&rc) == 0 && wait1(&rc) == 0 && rec.n_delete == 1);  /* larval SA is deletable */
	rc.seq = 33;
	CHECK(rcpfk_send_delete(&rc) == 0 && wait1(&rc) == -1 && rc.eno == ENOENT);  /* already gone */
	rc.satype = RCT_SATYPE_ESP;

	/* unsupported things fail cleanly instead of sending garbage */
	CHECK(rcpfk_send_migrate(&rc) == -1 && rc.eno == EOPNOTSUPP);
	rc.satype = RCT_SATYPE_IPCOMP;
	CHECK(rcpfk_send_getspi(&rc) == -1 && rc.eno == EOPNOTSUPP);
	rc.satype = RCT_SATYPE_ESP; rc.enctype = RCT_ALG_DES_CBC_IV64;
	CHECK(rcpfk_send_add(&rc) == -1 && rc.eno == EINVAL);
	rc.enctype = RCT_ALG_AES_GCM; rc.enckeylen = 200;
	CHECK(rcpfk_send_add(&rc) == -1 && rc.eno == EINVAL);        /* oversized key */

#ifdef RCPFK_ABI_VERSION
	/* flow selectors the forwarder can't honour are refused, not dropped */
	rc.enctype = RCT_ALG_AES_GCM; rc.enckeylen = sizeof(key);
	rc.mark = 0x10; rc.mark_mask = 0xff;
	CHECK(rcpfk_send_add(&rc) == -1 && rc.eno == EOPNOTSUPP);
	CHECK(rcpfk_send_spdadd(&rc) == -1 && rc.eno == EOPNOTSUPP);
	rc.mark = rc.mark_mask = 0; rc.if_id = 7;
	CHECK(rcpfk_send_spdadd(&rc) == -1 && rc.eno == EOPNOTSUPP);
	rc.if_id = 0;
	/* offload hints are not selectors: accepted */
	strcpy(rc.offload_ifname, "eth9");
	rc.seq = 99;
	CHECK(rcpfk_send_get(&rc) == 0);
	(void)wait1(&rc);		/* reply is ENOENT (SA already deleted); we only need it consumed */
#endif
	/* ---- EXPIRE pushed by the forwarder arrives as cb_expire, with what iked inspects ---- */
	{
		struct timeval tv = { .tv_sec = 6 };
		struct sockaddr_in esrc, edst;
		sin4(&esrc, "198.51.100.1", 0); sin4(&edst, "198.51.100.2", 0);
		setsockopt(rc.so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));      /* never hang the suite */
		memset(&rc.sa_natoa_src, 0, sizeof(rc.sa_natoa_src)); memset(&rc.sa_natoa_dst, 0, sizeof(rc.sa_natoa_dst));
		rc.sa_src = (struct sockaddr *)&esrc; rc.sa_dst = (struct sockaddr *)&edst;
		rc.satype = RCT_SATYPE_ESP; rc.samode = RCT_IPSM_TUNNEL; rc.enctype = RCT_ALG_AES_GCM; rc.authtype = RCT_ALG_NON_AUTH;
		rc.enckey = (caddr_t)key; rc.enckeylen = sizeof(key); rc.authkeylen = 0;
		rc.saflags = 0; rc.wsize = 64; rc.natt_type = 0; rc.reqid = 5; rc.spi = htonl(0x5555); rc.seq = 300;
		rc.lft_soft_time = 1; rc.lft_hard_time = 3; rc.lft_soft_bytes = rc.lft_hard_bytes = 0;
		CHECK(rcpfk_send_add(&rc) == 0 && wait1(&rc) == 0);
		rc.flags &= ~PFK_FLAG_WAITREPLY;
		CHECK(rcpfk_handler(&rc) == 0);                                        /* blocks until the event (~1 s) */
		CHECK(rec.n_expire == 1 && rec.expired[0] == 1);                       /* soft */
		CHECK(rec.exp_spi == htonl(0x5555) && rec.exp_satype == RCT_SATYPE_ESP && rec.exp_samode == RCT_IPSM_TUNNEL);
		CHECK(rec.exp_alloc != 0);                                             /* else iked ignores it */
		CHECK(rec.exp_reqid == 5 && rec.exp_dst_ok);
		CHECK(rcpfk_handler(&rc) == 0);                                        /* hard, ~3 s */
		CHECK(rec.n_expire == 2 && rec.expired[1] == 2);
		/* an event that lands while a caller waits for its own reply goes to the scratch container */
		rc.spi = htonl(0x5556); rc.lft_soft_time = 1; rc.lft_hard_time = 0; rc.seq = 301;
		CHECK(rcpfk_send_add(&rc) == 0 && wait1(&rc) == 0);
		sleep(2);                                                              /* soft event is now queued */
		rc.seq = 302; rc.spi = htonl(0x5555);
		CHECK(rcpfk_send_get(&rc) == 0);                                       /* ENOENT reply queued BEHIND the event */
		(void)wait1(&rc);
		CHECK(rec.n_expire == 3 && rec.expired[2] == 1);                       /* event dispatched via scratch, exactly once */
		CHECK(rc.eno == ENOENT);                                               /* and our own reply was still delivered to rc */
	}

	CHECK(rcpfk_clean(&rc) == 0 && rc.so == -1);
	close(raw);
	kill(mock, SIGTERM); waitpid(mock, NULL, 0);
	unlink(sock); rmdir(dir);

	if (fails) { fprintf(stderr, "%d check(s) failed\n", fails); return 1; }
	puts("shim_contract ok");
	return 0;
}

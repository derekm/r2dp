/*
 * ctl_unit: white-box tests of the r2dp control server (fwd/ctl.c is
 * included directly) against a fake dataplane that records every call.
 * Requests are dispatched in-process; replies are read from the client end
 * of a socketpair.
 */
#include "../fwd/ctl.c"

static int fails;
#define CHECK(c, ...) do { if (c) { printf("ok   "); printf(__VA_ARGS__); \
	putchar('\n'); } else { printf("FAIL "); printf(__VA_ARGS__); \
	putchar('\n'); fails++; } } while (0)

/* ---- fake dataplane ---- */
static int fk_last_flags = -1, fk_sa_calls, fk_sp_fail, fk_sa_fail;
static struct r2dp_sp fk_last_sp;

static int
fk_sa_add(struct fwd_dp *dp, int add, const struct r2dp_sa *sa,
    const void *blob, size_t blen)
{
	(void)dp; (void)sa; (void)blob; (void)blen;
	fk_sa_calls++;
	fk_last_flags = add;
	return fk_sa_fail;
}

static int
fk_sp_add(struct fwd_dp *dp, struct r2dp_sp *sp)
{
	(void)dp;
	if (fk_sp_fail)
		return fk_sp_fail;
	fk_last_sp = *sp;
	return 0;
}

static int
fk_sp_del(struct fwd_dp *dp, const struct r2dp_sp *sp)
{
	(void)dp; (void)sp;
	return 0;
}

static const struct fwd_dp_ops fk_ops = {
	.sa_add = fk_sa_add, .sp_add = fk_sp_add, .sp_del = fk_sp_del,
};

static struct fwd_ctl ctl;
static int sv[2];       /* sv[0] = server end, sv[1] = client end */

/* Dispatch one request and return the reply status (or -1 on no reply). */
static int
req(uint16_t type, uint32_t flags, const void *body, size_t blen,
    const void *tail, size_t tlen, struct r2dp_msg *reply)
{
	static struct r2dp_msg m;
	struct r2dp_msg r;
	static uint32_t seq = 100;

	memset(&m, 0, sizeof(m));
	m.h.magic = R2DP_MAGIC; m.h.version = R2DP_VERSION;
	m.h.type = type; m.h.seq = ++seq; m.h.flags = flags;
	m.h.len = (uint32_t)(sizeof(m.h) + blen + tlen);
	memcpy(m.body, body, blen);
	if (tlen)
		memcpy(m.body + blen, tail, tlen);
	dispatch(sv[0], &m);
	{
		struct pollfd p = { .fd = sv[1], .events = POLLIN };
		if (poll(&p, 1, 1000) != 1)
			return -1;
	}
	if (r2dp_recv(sv[1], &r) < 0)
		return -1;
	if (reply)
		*reply = r;
	return (int)r.h.status;
}

static void
mk_sa(struct r2dp_sa *sa, uint32_t spi_host)
{
	memset(sa, 0, sizeof(*sa));
	sa->proto = R2DP_PROTO_ESP; sa->mode = R2DP_MODE_TUNNEL;
	sa->enc = R2DP_ENCR_AES_GCM_16;
	sa->spi = htonl(spi_host);
	sa->src.family = sa->dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "192.0.2.2", sa->src.addr);
	inet_pton(AF_INET, "192.0.2.1", sa->dst.addr);
}

static uint32_t
getspi(void)
{
	struct r2dp_sa sa;
	struct r2dp_msg r;

	mk_sa(&sa, 0);
	if (req(R2DP_GETSPI, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, &r) != 0)
		return 0;
	return r2dp_msg_sa(&r)->spi;
}

/* ---- tests ---- */
static void
t_direction(void)
{
	struct r2dp_sa sa;
	uint8_t key[20] = { 0 };
	uint32_t spi;

	sa.enckeylen = 20;
	/* v1 inference: dir unset, completes our GETSPI -> inbound */
	spi = getspi();
	mk_sa(&sa, 0); sa.spi = spi; sa.enckeylen = 20;
	CHECK(req(R2DP_SA_UPDATE, 0, &sa, sizeof(sa), key, 20, NULL) == 0,
	    "dir=0 UPDATE of GETSPI larval");
	CHECK(fk_last_flags & FWD_DP_SA_INBOUND, "dir=0 larval -> INBOUND");

	/* explicit OUT overrides the larval inference */
	spi = getspi();
	mk_sa(&sa, 0); sa.spi = spi; sa.enckeylen = 20; sa.dir = R2DP_DIR_OUT;
	CHECK(req(R2DP_SA_UPDATE, 0, &sa, sizeof(sa), key, 20, NULL) == 0,
	    "dir=OUT UPDATE of larval");
	CHECK(!(fk_last_flags & FWD_DP_SA_INBOUND), "explicit dir=OUT honoured");

	/* explicit IN on a fresh ADD (no GETSPI) */
	mk_sa(&sa, 0x7777); sa.enckeylen = 20; sa.dir = R2DP_DIR_IN;
	CHECK(req(R2DP_SA_ADD, 0, &sa, sizeof(sa), key, 20, NULL) == 0,
	    "dir=IN fresh ADD");
	CHECK(fk_last_flags & FWD_DP_SA_INBOUND, "explicit dir=IN honoured");

	/* dir unset fresh ADD -> outbound (v1 behaviour) */
	mk_sa(&sa, 0x7778); sa.enckeylen = 20;
	CHECK(req(R2DP_SA_ADD, 0, &sa, sizeof(sa), key, 20, NULL) == 0,
	    "dir=0 fresh ADD");
	CHECK(!(fk_last_flags & FWD_DP_SA_INBOUND), "dir=0 fresh ADD -> outbound");
}

int
main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGPIPE, SIG_IGN);
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0)
		return 2;
	fwd_ctl_init(&ctl, NULL, 0);
	ctl.dp.ops = &fk_ops;

	t_direction();

	if (fails) { printf("ctl_unit: %d failures\n", fails); return 1; }
	puts("ctl_unit: OK");
	return 0;
}

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

static void
mk_sp(struct r2dp_sp *sp, const char *src, uint8_t ps, const char *dst, uint8_t pd)
{
	memset(sp, 0, sizeof(*sp));
	sp->dir = R2DP_DIR_OUT; sp->action = R2DP_ACT_PROTECT;
	sp->mode = R2DP_MODE_TUNNEL; sp->protos = R2DP_SPP_ESP;
	sp->ul_proto = R2DP_PROTO_ANY; sp->level = R2DP_LVL_REQUIRE;
	sp->sel_src.family = sp->sel_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, src, sp->sel_src.addr);
	inet_pton(AF_INET, dst, sp->sel_dst.addr);
	sp->pref_src = ps; sp->pref_dst = pd;
}

static void
t_reserved_spi(void)
{
	struct r2dp_sa sa;

	mk_sa(&sa, 0);
	sa.spi_min = 1; sa.spi_max = 0x200;
	CHECK(req(R2DP_GETSPI, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, NULL) == EINVAL,
	    "GETSPI range reaching reserved SPIs 1..255 refused");
	sa.spi_min = 0x100; sa.spi_max = 0x100;
	CHECK(req(R2DP_GETSPI, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, NULL) == 0,
	    "GETSPI at 0x100 allowed");
}

static void
t_prefix(void)
{
	struct r2dp_sp sp;

	mk_sp(&sp, "10.0.0.0", 33, "10.1.0.0", 16);
	CHECK(req(R2DP_SP_ADD, 0, &sp, sizeof(sp), NULL, 0, NULL) == EINVAL,
	    "v4 pref_src 33 refused");
	mk_sp(&sp, "10.0.0.0", 8, "10.1.0.0", 200);
	CHECK(req(R2DP_SP_ADD, 0, &sp, sizeof(sp), NULL, 0, NULL) == EINVAL,
	    "v4 pref_dst 200 refused");
	mk_sp(&sp, "10.0.0.0", 32, "10.1.0.0", 0);
	CHECK(req(R2DP_SP_ADD, 0, &sp, sizeof(sp), NULL, 0, NULL) == 0,
	    "v4 /32 -> /0 accepted");
}

static void
t_lifetime_clock(void)
{
	struct r2dp_sa sa;
	struct fwd_sa_ent *e;
	uint8_t key[20] = { 0 };

	mk_sa(&sa, 0x9001); sa.enckeylen = 20; sa.lft_hard_time = 100;
	CHECK(req(R2DP_SA_ADD, 0, &sa, sizeof(sa), key, 20, NULL) == 0, "ADD for clock test");
	e = sa_find(C, &sa);
	if (!e) { CHECK(0, "SA present"); return; }
	e->installed_at -= 50;            /* pretend 50s elapsed */
	{
		time_t t0 = e->installed_at;
		mk_sa(&sa, 0x9001); sa.lft_hard_time = 200;
		CHECK(req(R2DP_SA_UPDATE, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, NULL) == 0,
		    "lifetime-only UPDATE");
		CHECK(e->installed_at == t0, "lifetime-only UPDATE keeps the clock");
		CHECK(e->sa.lft_hard_time == 200, "new hard lifetime applied");
	}
}

static void
t_sp_upsert(void)
{
	struct r2dp_sp sp;
	struct r2dp_msg r;
	uint32_t slid;
	struct fwd_sp_ent *e;

	mk_sp(&sp, "10.9.0.0", 16, "10.8.0.0", 16);
	CHECK(req(R2DP_SP_ADD, 0, &sp, sizeof(sp), NULL, 0, &r) == 0, "SP_ADD base");
	slid = r2dp_msg_sp(&r)->slid;

	/* upsert refused by the dataplane: previous policy kept */
	sp.flags = R2DP_SPF_UPDATE; sp.action = R2DP_ACT_DISCARD;
	fk_sp_fail = EIO;
	CHECK(req(R2DP_SP_ADD, 0, &sp, sizeof(sp), NULL, 0, NULL) == EIO,
	    "failed upsert reports dp error");
	fk_sp_fail = 0;
	{
		struct r2dp_sp k; memset(&k, 0, sizeof(k)); k.slid = slid;
		e = sp_find(C, &k, 0);
	}
	CHECK(e && e->used && e->sp.action == R2DP_ACT_PROTECT,
	    "failed upsert keeps the previous policy");

	/* new add refused: slot stays free */
	mk_sp(&sp, "10.7.0.0", 16, "10.6.0.0", 16);
	fk_sp_fail = EIO;
	CHECK(req(R2DP_SP_ADD, 0, &sp, sizeof(sp), NULL, 0, NULL) == EIO, "failed add");
	fk_sp_fail = 0;
	CHECK(sp_find(C, &sp, 1) == NULL, "failed add leaves no ctl entry");

	/* client-chosen slid aliasing another policy */
	mk_sp(&sp, "10.5.0.0", 16, "10.4.0.0", 16); sp.slid = slid;
	CHECK(req(R2DP_SP_ADD, 0, &sp, sizeof(sp), NULL, 0, NULL) == EEXIST,
	    "client slid colliding with another policy refused");

	/* slid allocator skips 0 and in-use ids across wrap */
	C->next_slid = UINT32_MAX;
	mk_sp(&sp, "10.3.0.0", 16, "10.2.0.0", 16);
	CHECK(req(R2DP_SP_ADD, 0, &sp, sizeof(sp), NULL, 0, &r) == 0, "add at wrap");
	CHECK(r2dp_msg_sp(&r)->slid == UINT32_MAX, "slid UINT32_MAX handed out");
	mk_sp(&sp, "10.3.1.0", 24, "10.2.1.0", 24);
	CHECK(req(R2DP_SP_ADD, 0, &sp, sizeof(sp), NULL, 0, &r) == 0, "add after wrap");
	CHECK(r2dp_msg_sp(&r)->slid != 0 && r2dp_msg_sp(&r)->slid != slid,
	    "wrapped slid skips 0 and in-use ids (got %u)", r2dp_msg_sp(&r)->slid);
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
	t_reserved_spi();
	t_prefix();
	t_lifetime_clock();
	t_sp_upsert();

	if (fails) { printf("ctl_unit: %d failures\n", fails); return 1; }
	puts("ctl_unit: OK");
	return 0;
}

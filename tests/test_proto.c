/*
 * test_proto: unit tests for the r2dp wire contract and address helpers.
 *
 * Covers the layout assertions declared in proto.h (compiled in at build
 * time via _Static_assert), address round-trips, address equality, and
 * capability-bitmap queries.  No forwarder required.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "r2dp/client.h"

static int failures;

#define CHECK(cond, ...) do {                                                   \
	if (!(cond)) {                                                            \
		fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                 \
		fprintf(stderr, __VA_ARGS__);                                        \
		fputc('\n', stderr);                                                 \
		failures++;                                                          \
	}                                                                        \
} while (0)

/* proto.h must already assert these at compile time; sanity-check again. */
static void
layout(void)
{
	CHECK(sizeof(struct r2dp_hdr) == 24, "hdr size=%zu", sizeof(struct r2dp_hdr));
	CHECK(sizeof(struct r2dp_addr) == 24, "addr size=%zu", sizeof(struct r2dp_addr));
	CHECK(sizeof(struct r2dp_hello) == 16, "hello size=%zu", sizeof(struct r2dp_hello));
	CHECK(sizeof(struct r2dp_hello_ack) == 80, "ack size=%zu", sizeof(struct r2dp_hello_ack));
	CHECK(sizeof(struct r2dp_sa) == 200, "sa size=%zu", sizeof(struct r2dp_sa));
	CHECK(sizeof(struct r2dp_sp) == 152, "sp size=%zu", sizeof(struct r2dp_sp));
	CHECK(R2DP_CAP_WORDS * 32 > 28, "cap words cover max IANA id (28)");
}

static void
addr_v4(void)
{
	struct r2dp_addr a, b;
	struct sockaddr_storage st, st2;
	struct sockaddr *sa = (struct sockaddr *)&st;
	struct sockaddr_in *in = (struct sockaddr_in *)&st;
	int r;

	memset(&st, 0, sizeof(st));
	in->sin_family = AF_INET;
	inet_pton(AF_INET, "192.168.1.5", &in->sin_addr);
	in->sin_port = htons(5555);

	CHECK(r2dp_addr_from_sa(&a, sa) == 0, "from_sa v4");
	CHECK(a.family == R2DP_AF_INET4, "family=4 got=%u", a.family);
	CHECK(a.port == htons(5555), "port");
	CHECK(memcmp(a.addr, "\xc0\xa8\x01\x05", 4) == 0, "addr bytes");

	/* round trip */
	r = r2dp_addr_to_sa(&a, &st2);
	CHECK(r == 0, "to_sa v4 r=%d", r);
	CHECK(st2.ss_family == AF_INET, "ss family");
	{
		struct sockaddr_in *in2 = (struct sockaddr_in *)&st2;
		char buf[INET_ADDRSTRLEN];
		CHECK(in2->sin_port == htons(5555), "port rt");
		CHECK(inet_ntop(AF_INET, &in2->sin_addr, buf, sizeof(buf)) != NULL,
		    "ntop");
		CHECK(strcmp(buf, "192.168.1.5") == 0, "ntop == %s", buf);
	}

	/* equality */
	b = a;
	CHECK(r2dp_addr_eq(&a, &b) == 1, "eq same");
	b.port = 0;
	CHECK(r2dp_addr_eq(&a, &b) == 1, "eq ignores port");
	b.addr[3] = 9;
	CHECK(r2dp_addr_eq(&a, &b) == 0, "neq diff addr");
}

static void
addr_v6(void)
{
	struct r2dp_addr a;
	struct sockaddr_storage st;
	struct sockaddr *sa = (struct sockaddr *)&st;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&st;

	memset(&st, 0, sizeof(st));
	in6->sin6_family = AF_INET6;
	inet_pton(AF_INET6, "2001:db8::1", &in6->sin6_addr);
	in6->sin6_port = htons(4500);
	in6->sin6_scope_id = 7;

	CHECK(r2dp_addr_from_sa(&a, sa) == 0, "from_sa v6");
	CHECK(a.family == R2DP_AF_INET6, "family=6");
	CHECK(a.scope == 7, "scope=%u", a.scope);
	CHECK(memcmp(a.addr, "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16) == 0,
	    "v6 addr bytes");
}

static void
addr_unsupported(void)
{
	struct r2dp_addr a;
	struct sockaddr_storage st;
	struct sockaddr *sa = (struct sockaddr *)&st;

	CHECK(r2dp_addr_from_sa(&a, NULL) < 0, "null sa refused");
	CHECK(r2dp_addr_to_sa(&a, NULL) < 0, "null st refused");
	memset(&st, 0, sizeof(st));
	st.ss_family = AF_UNSPEC;
	CHECK(r2dp_addr_from_sa(&a, sa) < 0, "unspec refused");
	a.family = R2DP_AF_UNSET;
	{
		struct sockaddr_storage st2;
		CHECK(r2dp_addr_to_sa(&a, &st2) < 0, "unset to_sa refused");
	}
}

static void
caps(void)
{
	uint32_t caps[R2DP_CAP_WORDS];

	memset(caps, 0, sizeof(caps));
	CHECK(r2dp_cap(caps, 0) == 0, "empty bit 0");
	caps[0] = 1u << 12;			/* AES-CBC = 12 */
	CHECK(r2dp_cap(caps, 12) == 1, "bit 12 set");
	CHECK(r2dp_cap(caps, 11) == 0, "bit 11 clear");
	caps[2] = 1u << 0;			/* id 64 */
	CHECK(r2dp_cap(caps, 64) == 1, "word 2 bit 0");
	CHECK(r2dp_cap(caps, 8 * 32 + 1) == 0, "out of range clean");
}

static void
validate(void)
{
	struct r2dp_msg m;
	struct r2dp_sa *sa;
	size_t n;

	/* Truncated SA_ADD body (header only, no SA struct). */
	memset(&m, 0, sizeof(m));
	m.h.magic = R2DP_MAGIC; m.h.version = R2DP_VERSION;
	m.h.type = R2DP_SA_ADD; m.h.len = sizeof(m.h) + 10;
	n = sizeof(m.h) + 10;
	CHECK(r2dp_msg_validate(&m, n) == -EBADMSG, "truncated SA body rejected");

	/* No body for a HELLO_ACK. */
	m.h.type = R2DP_HELLO_ACK; m.h.len = sizeof(m.h);
	CHECK(r2dp_msg_validate(&m, sizeof(m.h)) == -EBADMSG, "short HELLO_ACK rejected");

	/* SA_ADD with enckeylen larger than the received tail -> OOB-cap guard. */
	memset(&m, 0, sizeof(m));
	m.h.magic = R2DP_MAGIC; m.h.version = R2DP_VERSION;
	m.h.type = R2DP_SA_ADD; m.h.len = sizeof(m.h) + sizeof(*sa) + 4;
	sa = (struct r2dp_sa *)r2dp_msg_sa(&m);
	sa->enckeylen = 100; sa->authkeylen = 0;   /* only 4 tail bytes present */
	n = m.h.len;
	CHECK(r2dp_msg_validate(&m, n) == -EBADMSG,
	    "keylen > tail rejected");

	/* SA_ADD NOKEYS with a non-empty tail. */
	m.h.flags = R2DP_HF_NOKEYS; m.h.len = sizeof(m.h) + sizeof(*sa) + 4;
	CHECK(r2dp_msg_validate(&m, m.h.len) == -EBADMSG, "NOKEYS with tail rejected");

	/* SA_ADD NOKEYS with exact no-tail body: ok. */
	m.h.len = sizeof(m.h) + sizeof(*sa);
	CHECK(r2dp_msg_validate(&m, m.h.len) == 0, "NOKEYS no-tail ok");

	/* SA_ADD with complete matching key tail: ok. */
	memset(&m, 0, sizeof(m));
	m.h.magic = R2DP_MAGIC; m.h.version = R2DP_VERSION;
	m.h.type = R2DP_SA_ADD; m.h.len = sizeof(m.h) + sizeof(*sa) + 20;
	sa = (struct r2dp_sa *)r2dp_msg_sa(&m);
	sa->enckeylen = 16; sa->authkeylen = 4;   /* AES-GCM 16+4 = 20 */
	CHECK(r2dp_msg_validate(&m, m.h.len) == 0, "full SA_ADD key tail ok");

	/* SA_ADD with key tail ordering mismatch. */
	m.h.len = sizeof(m.h) + sizeof(*sa) + 21;
	CHECK(r2dp_msg_validate(&m, m.h.len) == -EBADMSG, "tail length mismatch rejected");

	/* SA_DEL: key = full SA struct, no tail required. */
	memset(&m, 0, sizeof(m));
	m.h.magic = R2DP_MAGIC; m.h.version = R2DP_VERSION;
	m.h.type = R2DP_SA_DEL; m.h.len = sizeof(m.h) + sizeof(*sa);
	CHECK(r2dp_msg_validate(&m, m.h.len) == 0, "SA_DEL full key ok");
	m.h.len = sizeof(m.h) + sizeof(*sa) + 8;
	CHECK(r2dp_msg_validate(&m, m.h.len) == -EBADMSG, "SA_DEL with stray tail rejected");

	/* GETSPI / EXPIRE / ACQUIRE get the same tail rules as ADD/UPDATE:
	 * a non-NOKEYS SA whose enckeylen exceeds the tail is rejected, a
	 * NOKEYS SA must carry no tail. */
	{
		static const uint16_t ts[] = { R2DP_GETSPI, R2DP_EXPIRE, R2DP_ACQUIRE };
		for (unsigned i = 0; i < sizeof(ts) / sizeof(ts[0]); i++) {
			memset(&m, 0, sizeof(m));
			m.h.magic = R2DP_MAGIC; m.h.version = R2DP_VERSION;
			m.h.type = ts[i]; m.h.len = sizeof(m.h) + sizeof(*sa);
			sa = (struct r2dp_sa *)r2dp_msg_sa(&m);
			sa->enckeylen = 20;
			CHECK(r2dp_msg_validate(&m, m.h.len) == -EBADMSG,
			    "%s: enckeylen without tail rejected", r2dp_msg_name(ts[i]));
			m.h.flags = R2DP_HF_NOKEYS;
			CHECK(r2dp_msg_validate(&m, m.h.len) == 0,
			    "%s: NOKEYS no-tail ok", r2dp_msg_name(ts[i]));
			m.h.len += 4;
			CHECK(r2dp_msg_validate(&m, m.h.len) == -EBADMSG,
			    "%s: NOKEYS with tail rejected", r2dp_msg_name(ts[i]));
		}
	}

	/* Truncated SP_ADD body. */
	memset(&m, 0, sizeof(m));
	m.h.magic = R2DP_MAGIC; m.h.version = R2DP_VERSION;
	m.h.type = R2DP_SP_ADD; m.h.len = sizeof(m.h) + 40;
	const struct r2dp_sp *csp = r2dp_msg_sp(&m);
	(void)csp;
	CHECK(r2dp_msg_validate(&m, m.h.len) == -EBADMSG, "truncated SP body rejected");

	/* Unknown flag bits rejected. */
	memset(&m, 0, sizeof(m));
	m.h.magic = R2DP_MAGIC; m.h.version = R2DP_VERSION;
	m.h.type = R2DP_HELLO; m.h.len = sizeof(m.h) + sizeof(struct r2dp_hello);
	m.h.flags = 0x80000000;
	CHECK(r2dp_msg_validate(&m, m.h.len) == -EBADMSG, "unknown flag bits rejected");

	/* Unknown type: r2dp_recv converts to -ENOSYS, validate itself -EBADMSG. */
	m.h.flags = 0; m.h.type = R2DP_MSG_MAX;
	CHECK(r2dp_msg_validate(&m, m.h.len) == -EBADMSG, "unknown type rejected");
}

/* M1: a hung forwarder must not freeze r2dp_hello -- it times out.  Use a
 * socketpair where the peer never answers the HELLO. */
static void
hello_timeout(void)
{
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
		CHECK(0, "socketpair");
		return;
	}
	/* Benchmark-safe bound: poll() runs 5s of wall clock; cap the test so a
	 * hung HELLO can't take the suite down with it. */
	alarm(10);
	CHECK(r2dp_hello(sv[0], R2DP_ROLE_SPMD, NULL) == -ETIMEDOUT,
	    "hello times out against silent peer");
	alarm(0);
	close(sv[0]);
	close(sv[1]);
}

/* HELLO tolerates unsolicited EXPIRE ahead of the ACK, rejects an ACK for
 * a different seq, and maps an out-of-range status to -EPROTO. */
static int
queue_raw(int fd, uint16_t type, uint32_t seq, uint32_t status,
    const void *body, size_t blen)
{
	return r2dp_send(fd, type, seq, (int)status,
	    type == R2DP_EXPIRE ? R2DP_HF_NOKEYS : 0, body, blen, NULL, 0);
}

static void
hello_checks(void)
{
	struct r2dp_hello_ack ack, got;
	struct r2dp_sa sa;
	int sv[2];

	memset(&ack, 0, sizeof(ack));
	ack.epoch = 42; ack.max_msg = R2DP_MAX_MSG;
	memset(&sa, 0, sizeof(sa));

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) { CHECK(0, "sp"); return; }
	queue_raw(sv[1], R2DP_EXPIRE, 0, 0, &sa, sizeof(sa));
	queue_raw(sv[1], R2DP_HELLO_ACK, 0x48454c4fu, 0, &ack, sizeof(ack));
	memset(&got, 0, sizeof(got));
	CHECK(r2dp_hello(sv[0], R2DP_ROLE_IKED, &got) == 0 && got.epoch == 42,
	    "hello skips unsolicited EXPIRE before ACK");
	close(sv[0]); close(sv[1]);

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) { CHECK(0, "sp"); return; }
	queue_raw(sv[1], R2DP_HELLO_ACK, 7, 0, &ack, sizeof(ack));
	CHECK(r2dp_hello(sv[0], R2DP_ROLE_IKED, NULL) == -EPROTO,
	    "hello rejects ACK with foreign seq");
	close(sv[0]); close(sv[1]);

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) { CHECK(0, "sp"); return; }
	queue_raw(sv[1], R2DP_HELLO_ACK, 0x48454c4fu, 0x80000001u, &ack, sizeof(ack));
	CHECK(r2dp_hello(sv[0], R2DP_ROLE_IKED, NULL) == -EPROTO,
	    "hello maps out-of-range status to -EPROTO");
	close(sv[0]); close(sv[1]);

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) { CHECK(0, "sp"); return; }
	queue_raw(sv[1], R2DP_HELLO_ACK, 0x48454c4fu, EPERM, &ack, sizeof(ack));
	CHECK(r2dp_hello(sv[0], R2DP_ROLE_IKED, NULL) == -EPERM,
	    "hello surfaces errno-style status");
	close(sv[0]); close(sv[1]);
}

/* r2dp_send to a closed peer returns -EPIPE instead of raising SIGPIPE. */
static void
send_epipe(void)
{
	int sv[2];
	struct r2dp_hello h;

	memset(&h, 0, sizeof(h));
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) { CHECK(0, "sp"); return; }
	close(sv[1]);
	CHECK(r2dp_send(sv[0], R2DP_HELLO, 1, 0, 0, &h, sizeof(h), NULL, 0) == -EPIPE,
	    "send to closed peer -> -EPIPE (no SIGPIPE)");
	close(sv[0]);
}

int
main(void)
{
	layout();
	addr_v4();
	addr_v6();
	addr_unsupported();
	caps();
	validate();
	hello_timeout();
	hello_checks();
	send_epipe();

	if (failures) {
		fprintf(stderr, "test_proto: %d failure(s)\n", failures);
		return 1;
	}
	printf("test_proto: all ok\n");
	return 0;
}

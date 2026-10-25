/*
 * test_proto: unit tests for the r2dp wire contract and address helpers.
 *
 * Covers the layout assertions declared in proto.h (compiled in at build
 * time via _Static_assert), address round-trips, address equality, and
 * capability-bitmap queries.  No forwarder required.
 */
#include <stdio.h>
#include <string.h>
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

int
main(void)
{
	layout();
	addr_v4();
	addr_v6();
	addr_unsupported();
	caps();

	if (failures) {
		fprintf(stderr, "test_proto: %d failure(s)\n", failures);
		return 1;
	}
	printf("test_proto: all ok\n");
	return 0;
}

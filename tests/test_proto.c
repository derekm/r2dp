#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include "r2dp/client.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static size_t mk(struct r2dp_msg *m, unsigned type, size_t blen, size_t tlen, uint32_t flags)
{
	memset(m, 0, sizeof(*m));
	m->h.magic = R2DP_MAGIC; m->h.version = R2DP_VERSION; m->h.type = type;
	m->h.len = sizeof(m->h) + blen + tlen; m->h.flags = flags;
	return m->h.len;
}

int main(void)
{
	struct r2dp_msg m;
	struct r2dp_sa *sa = (struct r2dp_sa *)m.body;
	size_t n;

	/* enum sanity */
	CHECK(R2DP_MSG_MAX == R2DP_ACQUIRE + 1);

	/* well-formed messages */
	n = mk(&m, R2DP_HELLO, sizeof(struct r2dp_hello), 0, 0);
	CHECK(r2dp_validate(&m, n) == 0);
	n = mk(&m, R2DP_SP_ADD, sizeof(struct r2dp_sp), 0, 0);
	CHECK(r2dp_validate(&m, n) == 0);
	n = mk(&m, R2DP_SA_ADD, sizeof(*sa), 36 + 32, 0);
	sa->enckeylen = 36; sa->authkeylen = 32;
	CHECK(r2dp_validate(&m, n) == 0);
	n = mk(&m, R2DP_SA_GET, sizeof(*sa), 0, R2DP_HF_NOKEYS);
	sa->enckeylen = 36;                      /* informational with NOKEYS */
	CHECK(r2dp_validate(&m, n) == 0);

	/* malformed */
	n = mk(&m, R2DP_HELLO, sizeof(struct r2dp_hello), 0, 0);
	CHECK(r2dp_validate(&m, n - 1) == -EPROTO);          /* len != n */
	CHECK(r2dp_validate(&m, 10) == -EPROTO);             /* short header */
	m.h.magic ^= 1; CHECK(r2dp_validate(&m, n) == -EPROTO); m.h.magic ^= 1;
	m.h.version = 99; CHECK(r2dp_validate(&m, n) == -EPROTO); m.h.version = R2DP_VERSION;
	n = mk(&m, R2DP_HELLO, sizeof(struct r2dp_hello) - 4, 0, 0);
	CHECK(r2dp_validate(&m, n) == -EPROTO);              /* body too short */
	n = mk(&m, R2DP_SP_ADD, sizeof(struct r2dp_sp), 4, 0);
	CHECK(r2dp_validate(&m, n) == -EPROTO);              /* trailing junk */
	n = mk(&m, R2DP_SA_ADD, sizeof(*sa), 10, 0);
	sa->enckeylen = 36; sa->authkeylen = 0;
	CHECK(r2dp_validate(&m, n) == -EPROTO);              /* tail != keylens */
	n = mk(&m, R2DP_SA_ADD, sizeof(*sa), R2DP_MAX_KEY + 1, 0);
	sa->enckeylen = R2DP_MAX_KEY + 1; sa->authkeylen = 0;
	CHECK(r2dp_validate(&m, n) == -EPROTO);              /* key too long */
	n = mk(&m, R2DP_SA_GET, sizeof(*sa), 8, R2DP_HF_NOKEYS);
	sa->enckeylen = 0;
	CHECK(r2dp_validate(&m, n) == -EPROTO);              /* NOKEYS with tail */
	n = mk(&m, 0x7777, 0, 0, 0);
	CHECK(r2dp_validate(&m, n) == -ENOSYS);              /* unknown type */

	/* capability bitmap */
	{ uint32_t bm[8] = {0}; bm[20 >> 5] |= 1u << (20 & 31);
	  CHECK(r2dp_cap(bm, 20) && !r2dp_cap(bm, 19) && !r2dp_cap(bm, 300)); }

	/* address round trips */
	{
		struct sockaddr_in a4 = { .sin_family = AF_INET, .sin_port = htons(4500) };
		struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_port = htons(500),
		                           .sin6_scope_id = 7 };
		struct sockaddr_storage ss;
		struct r2dp_addr w;
		inet_pton(AF_INET, "192.0.2.9", &a4.sin_addr);
		inet_pton(AF_INET6, "2001:db8::1", &a6.sin6_addr);

		CHECK(r2dp_addr_from_sa(&w, (void *)&a4) == 0 && w.family == R2DP_AF_INET4);
		CHECK(r2dp_addr_to_sa(&w, &ss) == 0);
		CHECK(memcmp(&((struct sockaddr_in *)&ss)->sin_addr, &a4.sin_addr, 4) == 0);
		CHECK(((struct sockaddr_in *)&ss)->sin_port == a4.sin_port);

		CHECK(r2dp_addr_from_sa(&w, (void *)&a6) == 0 && w.family == R2DP_AF_INET6 && w.scope == 7);
		CHECK(r2dp_addr_to_sa(&w, &ss) == 0);
		CHECK(memcmp(&((struct sockaddr_in6 *)&ss)->sin6_addr, &a6.sin6_addr, 16) == 0);
		CHECK(((struct sockaddr_in6 *)&ss)->sin6_scope_id == 7);

		CHECK(r2dp_addr_from_sa(&w, NULL) == 0 && w.family == R2DP_AF_UNSET);
		CHECK(r2dp_addr_to_sa(&w, &ss) == 1);            /* UNSET */
		{ struct sockaddr sa_un = { .sa_family = AF_UNIX };
		  CHECK(r2dp_addr_from_sa(&w, &sa_un) == -EAFNOSUPPORT); }
	}

	if (fails) { fprintf(stderr, "%d check(s) failed\n", fails); return 1; }
	printf("test_proto ok (hdr=%zu sa=%zu sp=%zu)\n", sizeof(struct r2dp_hdr),
	       sizeof(struct r2dp_sa), sizeof(struct r2dp_sp));
	return 0;
}

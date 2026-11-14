/*
 * tests/xfrm_scrub.c -- KEYS KY1: the kernel backend's netlink buffers do
 * not keep SA key bytes after use.  Builds dp_xfrm.c into the test so its
 * static buffers and helpers are reachable; no netlink socket is needed.
 * Synthetic marker keys only.
 */
#include "../fwd/dp_xfrm.c"

static int fails;
#define CHECK(c, m) do { if (c) printf("ok   %s\n", m); \
	else { printf("FAIL %s\n", m); fails++; } } while (0)

static int
has_run(const uint8_t *b, size_t n, const uint8_t *pat, size_t pn)
{
	for (size_t i = 0; i + pn <= n; i++)
		if (!memcmp(b + i, pat, pn))
			return 1;
	return 0;
}

static int
all_zero(const void *p, size_t n)
{
	const uint8_t *b = p;
	for (size_t i = 0; i < n; i++)
		if (b[i])
			return 0;
	return 1;
}

int
main(void)
{
	struct r2dp_sa sa;
	struct nlb n;
	struct kx k;
	uint8_t key[36];

	memset(&sa, 0, sizeof(sa));
	memset(key, 0xc5, sizeof(key));
	sa.src.family = sa.dst.family = R2DP_AF_INET4;
	sa.src.addr[0] = 192; sa.src.addr[3] = 1;
	sa.dst.addr[0] = 192; sa.dst.addr[3] = 2;
	sa.spi = htonl(0x1001);
	sa.proto = R2DP_PROTO_ESP;
	sa.mode = R2DP_MODE_TUNNEL;
	sa.enc = R2DP_ENCR_AES_GCM_16;
	sa.enckeylen = 36;

	CHECK(build_sa(&n, XFRM_MSG_NEWSA, &sa, key, key + 36, 1) == 0,
	    "NEWSA built");
	CHECK(has_run(n.b, n.len, key, sizeof(key)),
	    "request carries the key bytes it must send");
	kx_wipe(&n);
	CHECK(all_zero(&n, sizeof(n)), "request buffer wiped after use");

	/* receive storage is wiped after an exchange, error paths included */
	memset(rbuf, 0xc5, sizeof(rbuf));
	memset(&k, 0, sizeof(k));
	k.fd = -1;
	{
		struct xfrm_usersa_id id;
		memset(&id, 0, sizeof(id));
		nlb_init(&n, XFRM_MSG_GETSA, 0, &id, sizeof(id));
	}
	CHECK(nl_xfer(&k, &n, NULL, 0, NULL, 0) == -EBADF &&
	    all_zero(rbuf, sizeof(rbuf)), "receive buffer wiped on failure");
	{
		int sv[2];
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0) {
			memset(rbuf, 0xc5, sizeof(rbuf));
			k.fd = sv[0];
			(void)nl_xfer(&k, &n, NULL, 0, NULL, 0);  /* send fails */
			CHECK(all_zero(rbuf, sizeof(rbuf)),
			    "receive buffer wiped after a failed send");
			close(sv[0]); close(sv[1]);
		}
	}
	if (fails) { printf("xfrm_scrub: %d failures\n", fails); return 1; }
	puts("xfrm_scrub: OK");
	return 0;
}

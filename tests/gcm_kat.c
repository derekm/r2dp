/*
 * gcm_kat: RFC 4106 AES-GCM-16 ESP known-answer test for the r2dp DPDK
 * dataplane.  Runs on the crypto_openssl vdev (no hugepages so it needs no
 * root/DPDK special setup) and guards the two fixes that previously made every
 * real ESP packet fail to decrypt:
 *   - ipsec_xform.direction must be INGRESS (EGRESS is enum 0, so an unset prm
 *     silently builds an encrypt SA and prepare() mangles received packets);
 *   - aad_length must be 8 (12 with ESN), the true RFC 4106 AAD = SPI||SeqNo;
 *     16 covers 8 extra zero bytes and fails every real peer.
 * It decrypts a packet sealed by OpenSSL EVP (a real external peer in the
 * crypto sense), checks st=0 and that the inner IPv4/ICMP comes back, and that
 * a tampered ICV is rejected.  Reverting either fix fails the checks.
 *
 * SKIP (77) if EAL or crypto_openssl is unavailable -- treat SKIP on a DPDK
 * lane as a failure, per the CI lane this backs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_cryptodev.h>
#include <rte_ipsec.h>
#include <rte_ipsec_sa.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_malloc.h>

#include "dp_gcm.h"

/* KEYMAT: 16-byte AES key || 4-byte salt (RFC 4106 s8.1 order) */
static uint8_t keymat[20] = {
    0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,
    0xcf,0x15,0x88,0x09,0xcf,0x4f,  0xf2,0x6b,0x58,0x0c };
#define SPI 0x1234u
static int cdev;
static struct rte_mempool *mp, *sess_mp, *cop_mp;
#define MAXSESS 8
static struct rte_ipsec_session *sess_tab[MAXSESS];
static size_t nsess;
static int fails = 0;
#define CHECK(c, m) do { if (c) { printf("ok   %s\n", m); } else { printf("FAIL %s\n", m); fails++; } } while (0)
#define IV_OFFSET (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))

static int
setup(void)
{
	struct rte_cryptodev_config cc; struct rte_cryptodev_qp_conf qc;
	cdev = rte_cryptodev_get_dev_id("crypto_openssl0");
	if (cdev < 0) return -1;
	memset(&cc, 0, sizeof(cc)); cc.socket_id = SOCKET_ID_ANY; cc.nb_queue_pairs = 1;
	if (rte_cryptodev_configure(cdev, &cc) < 0) return -1;
	memset(&qc, 0, sizeof(qc)); qc.nb_descriptors = 1024;
	if (rte_cryptodev_queue_pair_setup(cdev, 0, &qc, SOCKET_ID_ANY) < 0) return -1;
	if (rte_cryptodev_start(cdev) < 0) return -1;
	mp = rte_pktmbuf_pool_create("m", 256, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	sess_mp = rte_cryptodev_sym_session_pool_create("s", 32,
	    rte_cryptodev_sym_get_private_session_size(cdev), 0, 0, SOCKET_ID_ANY);
	cop_mp = rte_crypto_op_pool_create("c", RTE_CRYPTO_OP_TYPE_SYMMETRIC, 32, 0,
	    IV_OFFSET + 16, SOCKET_ID_ANY);
	return 0;
}

/* Build an INGRESS AES-GCM-16 tunnel session through the PRODUCTION
 * r2dp_gcm_sa_prm() (fwd/dp_gcm.c), so this guards the exact params the
 * forwarder installs.  `aad_tweak`, if nonzero, overrides aad_length to prove
 * the old 16 fails a real peer. */
static struct rte_ipsec_session *
mk_sess(unsigned aad_tweak)
{
	struct rte_ipsec_sa_prm prm; struct rte_crypto_sym_xform aead;
	struct rte_ipv4_hdr eh; size_t sz;
	struct r2dp_sa r; int ret;
	struct rte_ipsec_session *ss = rte_zmalloc(NULL, sizeof(*ss),
	    RTE_CACHE_LINE_SIZE);   /* rte_ipsec_session is 64-byte aligned */

	memset(&r, 0, sizeof(r));
	r.mode = R2DP_MODE_TUNNEL; r.enc = R2DP_ENCR_AES_GCM_16;
	r.enckeylen = 20; r.proto = R2DP_PROTO_ESP; r.spi = htonl(SPI);
	r.wsize = 64; r.saflags = 0;              /* no ESN -> aad_length 8 */
	r.src.family = r.dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "10.0.0.1", r.src.addr);
	inet_pton(AF_INET, "10.0.0.2", r.dst.addr);

	ret = r2dp_gcm_sa_prm(&r, keymat, 1, &prm, &aead, &eh);   /* inbound */
	if (ret < 0) { printf("prm=%d\n", ret); exit(2); }
	if (aad_tweak != 0)
		aead.aead.aad_length = aad_tweak;   /* simulate the old bug */

	sz = rte_ipsec_sa_size(&prm);
	if ((int)sz < 0) { puts("sa_size"); exit(2); }
	ss->sa = rte_zmalloc(NULL, sz, RTE_CACHE_LINE_SIZE);
	if (rte_ipsec_sa_init(ss->sa, &prm, sz) < 0) { puts("sa_init"); exit(2); }
	ss->type = RTE_SECURITY_ACTION_TYPE_NONE;
	ss->crypto.dev_id = cdev;
	ss->crypto.ses = rte_cryptodev_sym_session_create(cdev, &aead, sess_mp);
	if (!ss->crypto.ses) { puts("cses"); exit(2); }
	if (rte_ipsec_session_prepare(ss) < 0) { puts("sess"); exit(2); }
	if (nsess < MAXSESS)           /* track for teardown (D11/LeakSanitizer) */
		sess_tab[nsess++] = ss;
	return ss;
}

/* Teardown every session/pool the test created so gcm_kat is clean under
 * LeakSanitizer (the DPDK ASan CI lane fails on any leak). */
static void
teardown(void)
{
	for (size_t i = 0; i < nsess; i++) {
		struct rte_ipsec_session *ss = sess_tab[i];
		if (!ss) continue;
		if (ss->crypto.ses)
			rte_cryptodev_sym_session_free(cdev, ss->crypto.ses);
		if (ss->sa) { rte_ipsec_sa_fini(ss->sa); rte_free(ss->sa); }
		rte_free(ss);
	}
	nsess = 0;
	if (cop_mp) rte_mempool_free(cop_mp);
	if (sess_mp) rte_mempool_free(sess_mp);
	if (mp) rte_mempool_free(mp);
	if (cdev >= 0)
		rte_cryptodev_stop((uint8_t)cdev);
	rte_eal_cleanup();
}

/* Seal an ESP packet with OpenSSL EVP (real-peer crypto): takes the IP+ESP
 * body (outer IPv4 present), encrypts inner+trailer in place at offset 36.
 * Secure (RFC 4106): AAD = SPI||SeqNo (8), nonce = salt || esp-iv. */
static void
evp_seal(uint8_t *body, const uint8_t *inner, size_t il)
{
	uint8_t nonce[12]; uint8_t aad[8]; int l = 0;
	uint8_t pt[256]; size_t ptlen;

	/* ESP payload = inner + pad + pad_len + next(IPIP=4).  pad so (il+2)
	 * aligns to 4 (ESP pad length byte + next byte). */
	size_t padded = ((il + 2 + 3) / 4) * 4;
	size_t pad = padded - il - 2;
	memcpy(pt, inner, il);
	for (size_t i = 0; i < pad; i++) pt[il + i] = (uint8_t)(i + 1);
	pt[il + pad] = (uint8_t)pad;
	pt[il + pad + 1] = IPPROTO_IPIP;   /* next header */
	ptlen = padded;

	/* nonce = salt || esp-iv(from body offset 28..35) */
	memcpy(nonce, keymat + 16, 4);
	memcpy(nonce + 4, body + 28, 8);
	/* AAD = SPI || SeqNo (8 bytes), RFC 4106 s5 */
	memcpy(aad, body + 20, 4);
	memcpy(aad + 4, body + 24, 4);
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
	EVP_EncryptInit_ex(c, NULL, NULL, keymat, nonce);
	EVP_EncryptUpdate(c, NULL, &l, aad, 8);
	EVP_EncryptUpdate(c, body + 36, &l, pt, (int)ptlen);
	EVP_EncryptFinal_ex(c, body + 36 + l, &l);
	EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, body + 36 + ptlen);
	EVP_CIPHER_CTX_free(c);

	/* fix IP total_length: 20 IPv4 + 8 SPI/SEQ + 8 IV + ct + 16 ICV */
	uint16_t tot = 20 + 8 + 8 + (uint16_t)ptlen + 16;
	body[2] = (tot >> 8) & 0xff; body[3] = tot & 0xff;
}

static struct rte_mbuf *
mk_mbuf(const uint8_t *body, size_t n)
{
	struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
	memcpy(rte_pktmbuf_append(m, n), body, n);
	m->l2_len = 0; m->l3_len = 20; m->packet_type = RTE_PTYPE_L3_IPV4;
	return m;
}

static int
run(struct rte_ipsec_session *ss, struct rte_mbuf **m)
{
	struct rte_crypto_op *op = rte_crypto_op_alloc(cop_mp, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	int st;
	rte_crypto_op_attach_sym_session(op, ss->crypto.ses);
	if (rte_ipsec_pkt_crypto_prepare(ss, m, &op, 1) != 1) { rte_crypto_op_free(op); return -1; }
	if (rte_cryptodev_enqueue_burst(cdev, 0, &op, 1) != 1) return -3;
	while (rte_cryptodev_dequeue_burst(cdev, 0, &op, 1) == 0) ;
	st = op->status;
	if (st == 0)
		rte_ipsec_pkt_process(ss, m, 1);
	rte_crypto_op_free(op);
	return st;
}

int
main(void)
{
	char *ea[] = { "gcm_kat", "--no-huge", "--no-pci", "-m", "256",
	    "--vdev=crypto_openssl0", "--log-level=1", NULL };
	uint8_t body[200]; uint8_t inner[84]; size_t n;
	int st;

	if (rte_eal_init(7, ea) < 0) {
		/* D11: on a lane that requested DPDK, EAL failure must be a hard
		 * failure, not a pass-as-SKIP that hides a broken data plane. */
		if (getenv("R2DP_REQUIRE_DPDK")) { puts("EAL init FAILED"); return 1; }
		puts("SKIP: EAL"); return 77;
	}
	if (setup() < 0) {
		if (getenv("R2DP_REQUIRE_DPDK")) { puts("crypto_openssl FAILED"); return 1; }
		puts("SKIP: no crypto_openssl"); return 77;
	}

	/* build: outer IPv4 (20) + SPI(4)+SEQ(4) + IV(8) + ct + ICV(16) */
	memset(body, 0, sizeof(body));
	body[0] = 0x45;
	body[8] = 64; body[9] = IPPROTO_ESP;
	inet_pton(AF_INET, "10.0.0.1", &body[12]);
	inet_pton(AF_INET, "10.0.0.2", &body[16]);   /* outer dst = SAD DIP */
	body[20] = (SPI >> 24) & 0xff; body[21] = (SPI >> 16) & 0xff;
	body[22] = (SPI >> 8) & 0xff;  body[23] = SPI & 0xff;   /* SPI net order */
	body[24] = 0; body[25] = 0; body[26] = 0; body[27] = 1; /* SeqNo=1 */
	body[28] = 0x01; body[29] = 0x02; body[30] = 0x03; body[31] = 0x04;
	body[32] = 0x05; body[33] = 0x06; body[34] = 0x07; body[35] = 0x08; /* IV */

	/* inner 84-byte IPv4/ICMP echo (proto 01) */
	memset(inner, 0, 84);
	inner[0] = 0x45; inner[2] = 0; inner[3] = 84; inner[8] = 64; inner[9] = 1;
	inner[16] = 0x0a; inner[19] = 0x01;
	inner[20] = 0x0a; inner[23] = 0x02;
	inner[24] = 8; inner[25] = 0;   /* ICMP echo request */
	evp_seal(body, inner, 84);
	/* total = IPv4(20)+SPI/SEQ(8)+IV(8)+ct+ICV(16); ct=88 (84 inner + 4 trailer) */
	n = 20 + 8 + 8 + 88 + 16;

	/* AAD=8 (production): must decrypt */
	{ struct rte_mbuf *m = mk_mbuf(body, n);
	  st = run(mk_sess(0), &m);
	  CHECK(st == 0, "aad_length=8 decrypts real (EVP-sealed) ESP: st=0");
	  CHECK(st == 0 && m->pkt_len == 84 &&
	      ((uint8_t *)rte_pktmbuf_mtod(m, uint8_t *))[9] == 1,
	      "  inner IPv4/ICMP recovered (84 B, proto ICMP)");
	  rte_pktmbuf_free(m); }

	/* AAD=16 (the bug): must fail against the same real peer packet */
	{ struct rte_mbuf *m = mk_mbuf(body, n);
	  st = run(mk_sess(16), &m);
	  CHECK(st != 0, "aad_length=16 rejected by real peer (bogus ICV)");
	  rte_pktmbuf_free(m); }

	/* tampered ICV must be rejected */
	{ uint8_t bad[200]; memcpy(bad, body, n); bad[n - 1] ^= 1;
	  struct rte_mbuf *m = mk_mbuf(bad, n);
	  st = run(mk_sess(0), &m);
	  CHECK(st == RTE_CRYPTO_OP_STATUS_AUTH_FAILED ||
	        st == RTE_CRYPTO_OP_STATUS_ERROR,
	      "tampered ICV rejected");
	  rte_pktmbuf_free(m); }

	printf("%s\n", fails ? "FAIL" : "PASS");
	teardown();
	return fails ? 1 : 0;
}

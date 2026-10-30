/*
 * fwd/dp_gcm.c -- build the librte_ipsec SA parameters + AEAD xform for an
 * r2dp AES-GCM-16 tunnel SA.  Split out of dp_dpdk.c so the RFC 4106
 * known-answer test (tests/gcm_kat.c) exercises the exact production code.
 */
#ifdef R2DP_HAVE_DPDK
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_ip.h>

#include "dp_gcm.h"

int
r2dp_gcm_sa_prm(const struct r2dp_sa *rsa, const void *key, int inbound,
    struct rte_ipsec_sa_prm *prm, struct rte_crypto_sym_xform *aead,
    struct rte_ipv4_hdr *eh)
{
	uint32_t salt, src, dst;

	if (rsa->mode != R2DP_MODE_TUNNEL || rsa->enc != R2DP_ENCR_AES_GCM_16)
		return -EOPNOTSUPP;
	/* AES-GCM-16 is an AEAD: the key blob is exactly cipher key (16) ||
	 * salt (4) and there is no separate integrity transform or key. */
	if (rsa->enckeylen != 20 || key == NULL)
		return -EINVAL;
	if (rsa->integ != R2DP_INTEG_NONE || rsa->authkeylen != 0)
		return -EINVAL;
	if (rsa->src.family != R2DP_AF_INET4 || rsa->dst.family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;
	memcpy(&src, rsa->src.addr, 4);
	memcpy(&dst, rsa->dst.addr, 4);

	memset(prm, 0, sizeof(*prm));
	memset(aead, 0, sizeof(*aead));

	/* salt is the last 4 bytes of the AEAD blob (cipher key || salt).
	 * memcpy'd into a host-order uint32_t but used as raw bytes: librte_ipsec
	 * treats ipsec_xform.salt as byte-copy, so this is correct for RFC 4106. */
	memcpy(&salt, (const uint8_t *)key + 16, 4);

	aead->type = RTE_CRYPTO_SYM_XFORM_AEAD;
	aead->aead.algo = RTE_CRYPTO_AEAD_AES_GCM;
	/* Crypto op and librte_ipsec SA direction MUST agree.  An SA whose SPI we
	 * allocated (GETSPI) protects traffic to us: INGRESS + DECRYPT.  Leaving
	 * ipsec_xform.direction at its zero default makes it EGRESS, so
	 * rte_ipsec_pkt_crypto_prepare runs the *outbound* tunnel prepare on a
	 * received ESP packet (prepends a new outer IP+ESP, grows the packet) and
	 * the DECRYPT session then fails the tag. */
	aead->aead.op = inbound ? RTE_CRYPTO_AEAD_OP_DECRYPT :
	    RTE_CRYPTO_AEAD_OP_ENCRYPT;
	aead->aead.key.length = 16;
	aead->aead.iv.length = R2DP_GCM_IV_LEN;
	/* IV lives in the crypto op's private area (right after op + sym_op),
	 * where librte_ipsec writes it during prepare and the cryptodev PMD
	 * (OpenSSL) reads it back via this offset.  iv.offset=0 would make the
	 * PMD read the session-pointer region as the IV -- near-NULL deref and
	 * a crash on the first packet.  Same IV_OFFSET convention ipsec-secgw
	 * uses. */
	aead->aead.iv.offset = sizeof(struct rte_crypto_op) +
	    sizeof(struct rte_crypto_sym_op);
	/* RFC 4106 s5: AAD = SPI || 32-bit SeqNo (8 bytes), or SPI || 64-bit ESN
	 * (12 bytes).  librte_ipsec fills a 16-byte aead_gcm_aad buffer, but the
	 * PMD authenticates only xform aad_length bytes of it; the trailing bytes
	 * are padding.  ipsec-secgw: aad_len = 8 (+4 with ESN).  16 here makes
	 * the tag cover 8 extra zero bytes -> AUTH_FAILED against any real peer
	 * (Linux XFRM, strongSwan); two r2dp ends would round-trip only because
	 * both make the same mistake. */
	aead->aead.aad_length = (rsa->saflags & R2DP_SAF_ESN) ? 12 : 8;
	aead->aead.digest_length = 16;
	aead->aead.key.data = (uint8_t *)key;
	prm->crypto_xform = aead;

	prm->ipsec_xform.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
	prm->ipsec_xform.direction = inbound ? RTE_SECURITY_IPSEC_SA_DIR_INGRESS :
	    RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
	prm->ipsec_xform.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL;
	prm->ipsec_xform.spi = ntohl(rsa->spi);
	prm->ipsec_xform.salt = salt;
	prm->ipsec_xform.options.esn = (rsa->saflags & R2DP_SAF_ESN) ? 1 : 0;
	/* 0 = anti-replay off (PF_KEY).  librte_ipsec still keeps a 64-packet
	 * window under ESN: it needs one to infer the high sequence bits. */
	prm->ipsec_xform.replay_win_sz = r2dp_sa_window(rsa);
	prm->ipsec_xform.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;

	memset(eh, 0, sizeof(*eh));
	eh->version_ihl = 0x45;
	eh->time_to_live = 64;
	eh->next_proto_id = IPPROTO_ESP;   /* OUTER IP carries ESP */
	memcpy(&eh->src_addr, &src, 4);
	memcpy(&eh->dst_addr, &dst, 4);
	prm->tun.hdr_len = sizeof(*eh);
	prm->tun.hdr_l3_off = 0;
	/* tun.next_proto is the INNER protocol (what rides inside the ESP
	 * tunnel), not ESP.  For an IPv4-in-IPv4 tunnel that is IPIP;
	 * rte_ipsec_sa_size returns -EINVAL if this is wrongly set to
	 * IPPROTO_ESP (fill_sa_type rejects the nested case). */
	prm->tun.next_proto = IPPROTO_IPIP;
	prm->tun.hdr = eh;

	return 0;
}
#endif

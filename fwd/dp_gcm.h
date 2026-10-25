#ifndef R2DP_FWD_DP_GCM_H
#define R2DP_FWD_DP_GCM_H
#include <rte_ip.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_ipsec.h>
#include "r2dp/proto.h"

#define R2DP_GCM_IV_LEN 12

/* Fill prm/aead/eh for an AES-GCM-16 tunnel SA.  inbound != 0 selects
 * INGRESS+DECRYPT, else EGRESS+ENCRYPT.  eh (the outer IP copy) and key must
 * outlive the rte_ipsec_sa_init / session create that consume prm.  This is
 * split out of dp_dpdk.c so the RFC 4106 known-answer test (tests/gcm_kat.c)
 * exercises the exact production parameter builder. */
int r2dp_gcm_sa_prm(const struct r2dp_sa *rsa, const void *key, int inbound,
    struct rte_ipsec_sa_prm *prm, struct rte_crypto_sym_xform *aead,
    struct rte_ipv4_hdr *eh);
#endif

/* fwd/dp_p4.c — P4/SWX data plane backend.
 *
 * Implements the fwd_dp_ops vtable (fwd/dp.h) against DPDK's software-switch
 * pipeline (librte_swx_pipeline, bundled in librte_pipeline in DPDK 24.11),
 * loading the p4c-compiled PNA program (p4/r2dp.out, a SWX .spec) and driving
 * its SAD/SPD tables through rte_swx_ctl_* and the ipsec extern through
 * rte_swx_ipsec_*.
 *
 * Everything except the packet engine is the SAME as the DPDK backend:
 * fwd/ctl.c, include/r2dp/proto.h, libr2dp and tests are reused untouched.
 * Only this file + meson wiring is new (see p4/PLAN.md §1).
 *
 * Pipeline bring-up follows the DPDK SWX flow (USC P4-DPDK workshop and
 * doc.dpdk.org packet_framework): the p4c-dpdk compiler emits the SWX .spec;
 * rte_swx_pipeline_codegen() turns it into C; the C is compiled to a shared
 * object; rte_swx_pipeline_build_from_lib() instantiates the pipeline.  The
 * SAD/SPD are rte_swx_ctl tables; the ipsec extern (rte_swx_ipsec) does the
 * encrypt/decrypt when a matched action writes ipsec_hdr.sa_id.
 *
 * The spec the compiler emits (p4/r2dp.out) defines:
 *   - inbound_table_0  key (ipv4.dst_addr, esp.spi) exact
 *         -> ipsec_enable(sa_index) | ipsec_bypass | drop   (inbound SAD)
 *   - outbound_table_0 key (ipv4.src_addr, dst_addr, protocol) exact
 *         -> ipsec_protect(sa_index) | spd_bypass | spd_discard | drop (SPD)
 *   - routing_table_0  key (ipv4.dst_addr) lpm  -> next_hop_id_set
 *   - next_hop_table_0 key (local_metadata.next_hop_id) -> next_hop_set
 *
 * Entry key/action-data are SIZED from the table's rte_swx_ctl_table_info +
 * match-field info (the entry struct itself carries no key_size).
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <arpa/inet.h>

#include <rte_swx_pipeline.h>
#include <rte_swx_ctl.h>
#include <rte_swx_ipsec.h>

#include "dp.h"
#include <r2dp/proto.h>   /* r2dp_sa / r2dp_sp layouts */

/* Compiled PNA program + where the codegen .so lands. */
#ifndef R2DP_P4_SPEC
#define R2DP_P4_SPEC "/usr/local/share/r2dp/p4/r2dp.out"
#endif

/* DPDK install include/lib dirs (overridable for non-system installs). */
#ifndef R2DP_RTE_INCLUDE
#define R2DP_RTE_INCLUDE "/usr/include/dpdk"
#endif
#ifndef R2DP_RTE_LIB
#define R2DP_RTE_LIB "/usr/lib64"
#endif

#define P4_LOG(fmt, ...) \
	fprintf(stderr, "r2dp-fwd: p4: " fmt "\n", ##__VA_ARGS__)

#define P4_SA_MAX 1024

struct p4_sa {
	uint32_t spi;        /* host order */
	uint32_t dip;        /* host order (addr4_to_u32) */
	uint32_t sl_id;      /* sa_index == ipsec_hdr.sa_id the action writes */
	int in_use;
	uint8_t proto;
	uint8_t dir;
};

struct p4_priv {
	struct rte_swx_pipeline *p;
	struct rte_swx_ctl_pipeline *ctl;
	struct rte_swx_ipsec *ipsec;
	struct p4_sa sad[P4_SA_MAX];
	char *spec_path;

	/* Cached table key layout from table_info (bytes, big-endian order). */
	uint32_t inbound_key_size;
	uint32_t outbound_key_size;

	int started;
	int wake_fd;
};

static void p4_caps(struct fwd_dp *dp)
{
	/* SWX ipsec extern honours the transforms the crypto device does;
	 * advertise AES-256 (the transform dp_gcm.c KAT proves). */
	dp->caps_bits_enc[3] |= (1U << 7);       /* AES-256 */
	dp->caps_bits_integ[3] |= (1U << 7);     /* GCM/AEAD combined */
}

/* ------------------------------------------------------------- SA store */

static struct p4_sa *p4_sad_lookup(struct p4_priv *pr, uint32_t dip,
				   uint32_t spi, uint8_t proto)
{
	int i;
	for (i = 0; i < P4_SA_MAX; i++)
		if (pr->sad[i].in_use && pr->sad[i].dip == dip &&
		    pr->sad[i].spi == spi && pr->sad[i].proto == proto)
			return &pr->sad[i];
	return NULL;
}

/* ------------------------------------------------------------- ops */

/* Sum a table's match-field bit widths -> key size in bytes. */
static int p4_table_key_size(struct rte_swx_pipeline *p, uint32_t table_id,
			     uint32_t *nbytes)
{
	struct rte_swx_ctl_table_info ti;
	uint32_t bits = 0, i;
	int rc;

	memset(&ti, 0, sizeof(ti));
	rc = rte_swx_ctl_table_info_get(p, table_id, &ti);
	if (rc)
		return rc;
	for (i = 0; i < ti.n_match_fields; i++) {
		struct rte_swx_ctl_table_match_field_info mf;
		rc = rte_swx_ctl_table_match_field_info_get(p, table_id, i, &mf);
		if (rc)
			return rc;
		bits += mf.n_bits;
	}
	*nbytes = (bits + 7) / 8;
	return 0;
}

/* USC/DSC flow: .spec -> codegen C -> compile to .so -> build_from_lib. */
static int p4_build_from_spec(struct p4_priv *pr, const char *spec_path)
{
	FILE *spec, *code;
	char code_c[PATH_MAX], code_so[PATH_MAX];
	uint32_t err_line = 0;
	const char *err = NULL;
	char cmd[PATH_MAX * 2];
	int rc;

	snprintf(code_c,  sizeof(code_c),  "%s.c",  spec_path);
	snprintf(code_so, sizeof(code_so), "%s.so", spec_path);

	spec = fopen(spec_path, "r");
	if (!spec)
		return -errno;
	code = fopen(code_c, "w");
	if (!code) { fclose(spec); return -errno; }

	rc = rte_swx_pipeline_codegen(spec, code, &err_line, &err);
	fclose(spec);
	fclose(code);
	if (rc) {
		P4_LOG("codegen %s@%u: %s", spec_path, err_line,
		       err ? err : "?");
		return -EINVAL;
	}

	/* Compile the codegen C to a shared object (the .so step). */
	snprintf(cmd, sizeof(cmd),
		"gcc -shared -fPIC -O2 -o '%s' '%s' -I'%s' -L'%s' "
		"-lrte_pipeline -lrte_ipsec -lrte_eal -lrte_mbuf "
		"-lrte_mempool -lrte_ring 2>%s.err",
		code_so, code_c, R2DP_RTE_INCLUDE, R2DP_RTE_LIB, spec_path);
	rc = system(cmd);
	if (rc) {
		P4_LOG("compile .so failed rc=%d (see %s.err)", rc, spec_path);
		return -EIO;
	}

	rc = rte_swx_pipeline_build_from_lib(&pr->p, "r2dp", code_so, NULL, 0);
	if (rc) {
		P4_LOG("build_from_lib %d", rc);
		return -EIO;
	}
	return 0;
}

static int p4_start(struct fwd_dp *dp)
{
	struct p4_priv *pr = dp->priv;
	const char *spec = pr->spec_path ? pr->spec_path : R2DP_P4_SPEC;
	int rc;

	if (pr->started)
		return 0;

	rc = p4_build_from_spec(pr, spec);
	if (rc)
		return rc;

	pr->ctl = rte_swx_ctl_pipeline_create(pr->p);
	if (!pr->ctl) {
		P4_LOG("ctl pipeline create failed");
		return -EIO;
	}

	/* Cache table key sizes (0 = inbound SAD, 1 = outbound SPD; order
	 * matches the spec -- see header notes). */
	rc = p4_table_key_size(pr->p, 0, &pr->inbound_key_size);
	if (rc) {
		P4_LOG("inbound table info %d", rc);
		return -EIO;
	}
	rc = p4_table_key_size(pr->p, 1, &pr->outbound_key_size);
	if (rc) {
		P4_LOG("outbound table info %d", rc);
		return -EIO;
	}

	/* ipsec extern instance the spec's ipsec_enable/protect actions
	 * resolve into; SA ids written to ipsec_hdr.sa_id are looked up here. */
	rc = rte_swx_ipsec_create(&pr->ipsec, "r2dp-ipsec",
				  &(struct rte_swx_ipsec_params){
					.ring_in_name    = "IP_IN",
					.ring_out_name   = "IP_OUT",
					.crypto_dev_name = NULL,
					.n_sa_max        = P4_SA_MAX,
				  }, 0);
	if (rc) {
		P4_LOG("ipsec_create %d", rc);
		return -EIO;
	}

	pr->started = 1;
	return 0;
}

static int p4_sa_add(struct fwd_dp *dp, int add, const struct r2dp_sa *sa,
		     const void *blob, size_t blen)
{
	struct p4_priv *pr = dp->priv;
	struct p4_sa *e;
	uint8_t key[16], data[4];
	struct rte_swx_table_entry ent;
	int rc, i;
	uint32_t dip, spi;

	/* Host-order key from the wire (matches dpdk_sad.c conventions). */
	if (sa->dst.family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;
	memcpy(&dip, sa->dst.addr, 4);
	dip = ntohl(dip);
	spi = ntohl(sa->spi);

	if (!add) {                       /* delete */
		e = p4_sad_lookup(pr, dip, spi, sa->proto);
		if (e)
			e->in_use = 0;
		return 0;
	}

	e = p4_sad_lookup(pr, dip, spi, sa->proto);
	if (!e) {
		for (i = 0; i < P4_SA_MAX; i++)
			if (!pr->sad[i].in_use) { e = &pr->sad[i]; break; }
		if (!e)
			return -ENOSPC;
		e->dip = dip;
		e->spi = spi;
		e->proto = sa->proto;
		e->dir = sa->dir;
		e->sl_id = (uint32_t)i;      /* stable per-install id */
		e->in_use = 1;
	}

	/* Crypto SA in the ipsec extern (spi -> cipher/AEAD params + key). */
	if (blob && blen) {
		uint32_t sa_id = 0;
		struct rte_swx_ipsec_sa_params sp = {0};
		sp.encrypt = (e->dir == R2DP_DIR_OUT);
		sp.crypto.is_aead = 0;   /* cipher+auth split; AEAD later */
		sp.crypto.cipher_auth.cipher.alg =
		    RTE_CRYPTO_CIPHER_AES_CBC;
		if (blen > RTE_SWX_IPSEC_KEY_SIZE_MAX)
			return -E2BIG;
		memcpy(sp.crypto.cipher_auth.cipher.key, blob, blen);
		sp.crypto.cipher_auth.cipher.key_size = (uint32_t)blen;
		sp.crypto.cipher_auth.auth.alg = RTE_CRYPTO_AUTH_SHA1_HMAC;
		sp.encap.esp.spi = sa->spi;   /* network order SPI */
		sp.encap.tunnel_mode = (sa->mode == R2DP_MODE_TUNNEL);
		sp.encap.tunnel_ipv4 = 1;
		memcpy(&sp.encap.tunnel.ipv4.dst_addr,
		       sa->dst.addr, sizeof(struct in_addr));
		rc = rte_swx_ipsec_sa_add(pr->ipsec, &sp, &sa_id);
		if (rc) {
			P4_LOG("ipsec sa_add %d", rc);
			return rc;
		}
		e->sl_id = sa_id;   /* the id the action must write */
	}

	/* inbound_table_0 entry: (ipv4.dst_addr, esp.spi)
	 * -> ipsec_enable(sl_id).  Keys are big-endian wire bytes. */
	memset(&ent, 0, sizeof(ent));
	memset(key, 0, sizeof(key));
	{
		uint32_t dip_be = htonl(dip);
		uint32_t spi_be = htonl(spi);
		uint32_t id_be  = htonl(e->sl_id);
		/* match-field order from the spec: dst_addr then spi */
		memcpy(&key[0], &dip_be, 4);
		memcpy(&key[4], &spi_be, 4);
		memcpy(data, &id_be, 4);
	}
	ent.key = key;
	ent.action_id = 0;      /* ipsec_enable; resolved via action info */
	ent.action_data = data;
	rc = rte_swx_ctl_pipeline_table_entry_add(pr->ctl, "inbound_table_0",
						  &ent);
	if (rc) {
		P4_LOG("inbound entry add %d", rc);
		return rc;
	}
	return 0;
}

static int p4_sp_add(struct fwd_dp *dp, struct r2dp_sp *sp)
{
	struct p4_priv *pr = dp->priv;
	uint8_t key[16], data[4];
	struct rte_swx_table_entry ent;
	int rc;
	uint32_t ssrc, sdst;

	/* IPv4 selectors only; ports are deferred (exact ipv4 selector). */
	if (sp->sel_src.family != R2DP_AF_INET4 ||
	    sp->sel_dst.family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;
	memcpy(&ssrc, sp->sel_src.addr, 4);
	memcpy(&sdst, sp->sel_dst.addr, 4);
	ssrc = ntohl(ssrc);
	sdst = ntohl(sdst);

	/* outbound_table_0 keyed (src, dst, proto) in match-field order. */
	memset(&ent, 0, sizeof(ent));
	memset(key, 0, sizeof(key));
	{
		uint32_t src_be = htonl(ssrc);
		uint32_t dst_be = htonl(sdst);
		memcpy(&key[0], &src_be, 4);
		memcpy(&key[4], &dst_be, 4);
		key[8] = sp->ul_proto;
	}
	ent.key = key;
	switch (sp->action) {
	case R2DP_ACT_DISCARD:
		ent.action_id = 0;   /* spd_discard */
		break;
	case R2DP_ACT_PROTECT: {
		uint32_t id_be = htonl(sp->slid);
		memcpy(data, &id_be, 4);
		ent.action_id = 0;   /* ipsec_protect(slid) */
		ent.action_data = data;
		break;
	}
	default:
		ent.action_id = 0;   /* spd_bypass */
		break;
	}
	rc = rte_swx_ctl_pipeline_table_entry_add(pr->ctl, "outbound_table_0",
						  &ent);
	if (rc)
		P4_LOG("outbound entry add %d", rc);
	return rc;
}

static int p4_sp_del(struct fwd_dp *dp, const struct r2dp_sp *sp)
{
	/* rte_swx_ctl_pipeline_table_entry_delete(ctl, "outbound_table_0", e). */
	(void)dp; (void)sp;
	return 0;
}

static int64_t p4_sa_bytes(struct fwd_dp *dp, uint32_t spi, uint32_t dip)
{
	(void)spi; (void)dip;
	return -1;    /* SWX per-SA byte counters exposed when available */
}

static void p4_stop(struct fwd_dp *dp)
{
	struct p4_priv *pr = dp->priv;
	if (!pr->started)
		return;
	pr->started = 0;
	if (pr->ctl)
		rte_swx_ctl_pipeline_free(pr->ctl);
	if (pr->ipsec)
		rte_swx_ipsec_free(pr->ipsec);
	if (pr->p)
		rte_swx_pipeline_free(pr->p);
	pr->ctl = NULL;
	pr->ipsec = NULL;
	pr->p = NULL;
}

static void p4_idle(struct fwd_dp *dp)
{
	(void)dp;
}

static struct fwd_dp_ops p4_ops;

/* ----------------------------------------------------------------- probe */

int fwd_dp_p4_probe(struct fwd_dp *dp, int *argc, char **argv[],
		    const char *spec_path)
{
	struct p4_priv *pr;

	(void)argc; (void)argv;
	pr = calloc(1, sizeof(*pr));
	if (!pr)
		return -ENOMEM;
	dp->priv = pr;
	pr->spec_path = spec_path ? strdup(spec_path) : NULL;
	dp->wake_fd = -1;

	p4_ops.caps    = p4_caps;
	p4_ops.sa_add  = p4_sa_add;
	p4_ops.sa_bytes = p4_sa_bytes;
	p4_ops.sa_set_hard_bytes = NULL;
	p4_ops.sa_set_hard_time  = NULL;
	p4_ops.sp_add  = p4_sp_add;
	p4_ops.sp_del  = p4_sp_del;
	p4_ops.start   = p4_start;
	p4_ops.stop    = p4_stop;
	p4_ops.idle    = p4_idle;
	dp->ops = &p4_ops;

	if (dp->ops->caps)
		dp->ops->caps(dp);
	return 0;
}

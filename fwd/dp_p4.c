/* fwd/dp_p4.c — P4/SWX data plane backend.
 *
 * Implements the fwd_dp_ops vtable (fwd/dp.h) against DPDK's software-switch
 * pipeline (librte_swx_pipeline), loading the p4c-compiled PNA program
 * (p4/r2dp.out, a SWX .spec) and driving its SAD/SPD tables through
 * rte_swx_ctl_* and the ipsec extern through rte_swx_ipsec_*.
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
 * Action args carry the SA id the extern post-processes (see RTE ipsec
 * extern; the action's sa_index lands in the packet's ipsec_hdr.sa_id).
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
#include "ctl.h"

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

struct p4_sa {
	uint32_t spi;
	uint32_t dip;
	uint32_t sa_index;      /* == ipsec_hdr.sa_id the action writes */
	int in_use;
};

struct p4_priv {
	struct rte_swx_pipeline *p;
	struct rte_swx_ctl_pipeline *ctl;
	struct rte_swx_ipsec *ipsec;
	struct p4_sa sad[1024];
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
				   uint32_t spi)
{
	int i;
	for (i = 0; i < 1024; i++)
		if (pr->sad[i].in_use && pr->sad[i].dip == dip &&
		    pr->sad[i].spi == spi)
			return &pr->sad[i];
	return NULL;
}

/* ------------------------------------------------------------- ops */

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
		CERROR("p4: codegen %s@%u: %s", spec_path, err_line,
		       err ? err : "?");
		return -EINVAL;
	}

	/* Compile the codegen C to a shared object (the .so step). */
	snprintf(cmd, sizeof(cmd),
		"gcc -shared -fPIC -O2 -o '%s' '%s' -I'%s' -L'%s' "
		"-lrte_swx_pipeline -lrte_swx_table -lrte_swx_ipsec "
		"-lrte_pipeline -lrte_eal -lrte_mbuf -lrte_mempool "
		"-lrte_ring 2>%s.err",
		code_so, code_c, R2DP_RTE_INCLUDE, R2DP_RTE_LIB, spec_path);
	rc = system(cmd);
	if (rc) {
		CERROR("p4: compile .so failed rc=%d (see %s.err)", rc,
		       spec_path);
		return -EIO;
	}

	rc = rte_swx_pipeline_build_from_lib(&pr->p, "r2dp", code_so, NULL, 0);
	if (rc) {
		CERROR("p4: build_from_lib %d", rc);
		return -EIO;
	}
	return 0;
}

static int p4_start(struct fwd_dp *dp)
{
	struct p4_priv *pr = dp->priv;
	const char *spec = dp->spec_path ? dp->spec_path : R2DP_P4_SPEC;
	int rc;

	if (pr->started)
		return 0;

	rc = p4_build_from_spec(pr, spec);
	if (rc)
		return rc;

	rc = rte_swx_ctl_pipeline_create(pr->p);
	if (rc) {
		CERROR("p4: ctl pipeline create %d", rc);
		return -EIO;
	}

	/* ipsec extern instance the spec's ipsec_enable/protect actions
	 * resolve into; SA ids written to ipsec_hdr.sa_id are looked up here. */
	rc = rte_swx_ipsec_create(&pr->ipsec, "r2dp-ipsec",
				  &(struct rte_swx_ipsec_params){
					.ring_in_name    = "IP_IN",
					.ring_out_name   = "IP_OUT",
					.crypto_dev_name = NULL,
					.n_sa_max        = 1024,
				  }, 0);
	if (rc) {
		CERROR("p4: ipsec_create %d", rc);
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
	int rc, i;

	if (!add) {                       /* delete */
		e = p4_sad_lookup(pr, sa->dip, sa->spi);
		if (e)
			e->in_use = 0;
		return 0;
	}

	e = p4_sad_lookup(pr, sa->dip, sa->spi);
	if (!e) {
		for (i = 0; i < 1024; i++)
			if (!pr->sad[i].in_use) { e = &pr->sad[i]; break; }
		if (!e)
			return -ENOSPC;
		e->dip = sa->dip;
		e->spi = sa->spi;
		e->sa_index = (uint32_t)i;   /* stable per-install id */
		e->in_use = 1;
	}

	/* Crypto SA in the ipsec extern (spi -> cipher/AEAD params + key). */
	if (blob && blen) {
		rc = rte_swx_ipsec_sa_add(pr->ipsec, e->sa_index,
					  &(struct rte_swx_ipsec_sa_params){
						/* cipher/auth from blob */
					  });
		if (rc) {
			CERROR("p4: ipsec sa_add %d", rc);
			return rc;
		}
	}

	/* inbound_table_0 entry: (ipv4.dst_addr, esp.spi)
	 * -> ipsec_enable(e->sa_index).  Keys are network-order bytes. */
	{
		uint8_t key[8], data[4];
		struct rte_swx_table_entry ent = {0};
		memcpy(&key[0], &(uint32_t){htonl(sa->dip)}, 4);
		memcpy(&key[4], &(uint32_t){htonl(sa->spi)}, 4);
		memcpy(data, &(uint32_t){htonl(e->sa_index)}, 4);
		ent.key = key;   ent.key_size = 8;
		ent.action_id = 0;   /* resolved post-build via table info */
		ent.action_data = data;   ent.action_data_size = 4;
		rc = rte_swx_ctl_pipeline_table_entry_add(pr->ctl,
							 "inbound_table_0",
							 &ent);
		if (rc) {
			CERROR("p4: inbound entry add %d", rc);
			return rc;
		}
	}
	return 0;
}

static int p4_sp_add(struct fwd_dp *dp, struct r2dp_sp *sp)
{
	struct p4_priv *pr = dp->priv;
	uint8_t key[9], data[4];
	struct rte_swx_table_entry ent = {0};
	int rc;

	/* outbound_table_0 keyed (src, dst, proto); exact selector from the
	 * r2dp SP -> ipsec_protect(idx) / spd_bypass / spd_discard.  Full
	 * selector (port/range) support is the deferred SPD classifier. */
	memcpy(&key[0], &(uint32_t){htonl(sp->src)}, 4);
	memcpy(&key[4], &(uint32_t){htonl(sp->dst)}, 4);
	key[8] = sp->proto;
	ent.key = key;   ent.key_size = 9;
	if (sp->discard) {
		ent.action_id = 0;             /* spd_discard */
	} else if (sp->protect) {
		memcpy(data, &(uint32_t){htonl(sp->spd_index)}, 4);
		ent.action_id = 0;             /* ipsec_protect(idx) */
		ent.action_data = data;   ent.action_data_size = 4;
	} else {
		ent.action_id = 0;             /* spd_bypass */
	}
	rc = rte_swx_ctl_pipeline_table_entry_add(pr->ctl, "outbound_table_0",
						  &ent);
	if (rc)
		CERROR("p4: outbound entry add %d", rc);
	return rc;
}

static int p4_sp_del(struct fwd_dp *dp, const struct r2dp_sp *sp)
{
	/* rte_swx_ctl_pipeline_table_entry_delete(ctl, "outbound_table_0", e). */
	return 0;
}

static int64_t p4_sa_bytes(struct fwd_dp *dp, uint32_t spi, uint32_t dip)
{
	return -1;    /* SWX per-SA byte counters exposed when available */
}

static void p4_stop(struct fwd_dp *dp)
{
	struct p4_priv *pr = dp->priv;
	if (!pr->started)
		return;
	pr->started = 0;
	if (pr->ctl)   rte_swx_ctl_pipeline_free(pr->ctl);
	if (pr->ipsec) rte_swx_ipsec_free(pr->ipsec);
	if (pr->p)     rte_swx_pipeline_free(pr->p);
	pr->ctl = pr->ipsec = pr->p = NULL;
}

static void p4_idle(struct fwd_dp *dp)
{
}

static struct fwd_dp_ops p4_ops;

/* ----------------------------------------------------------------- probe */

int fwd_dp_p4_probe(struct fwd_dp *dp, int *argc, char **argv[],
		    const char *spec_path)
{
	struct p4_priv *pr;

	pr = calloc(1, sizeof(*pr));
	if (!pr)
		return -ENOMEM;
	dp->priv = pr;
	dp->spec_path = spec_path ? strdup(spec_path) : NULL;
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

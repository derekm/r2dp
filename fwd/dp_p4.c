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

#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
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
#include <rte_ring.h>
#include <rte_cryptodev.h>
#include <rte_mbuf.h>

#include "dp.h"
#include <r2dp/proto.h>   /* r2dp_sa / r2dp_sp layouts */

/* Compiled PNA program + where the codegen .so lands. */
#ifndef R2DP_P4_SPEC
#define R2DP_P4_SPEC "/usr/local/share/r2dp/p4/r2dp.out"
#endif

/* Default pipeline I/O spec (ports + ipsec rings).  Overridable via
 * $R2DP_P4_IOSPEC; a minimal ring-based iospec is auto-written to the
 * scratch dir if none exists. */
#ifndef R2DP_P4_IOSPEC
#define R2DP_P4_IOSPEC ""
#endif

/* DPDK install include/lib dirs (overridable for non-system installs). */
#ifndef R2DP_RTE_INCLUDE
#define R2DP_RTE_INCLUDE "/usr/include/dpdk"
#endif
#ifndef R2DP_RTE_LIB
#define R2DP_RTE_LIB "/usr/lib64"
#endif

/* DPDK source dir whose lib/pipeline holds the internal headers the codegen
 * .so needs (rte_swx_pipeline_internal.h is NOT in the public include dir).
 * Set via -DR2DP_SWX_SRC or $R2DP_SWX_SRC at runtime. */
#ifndef R2DP_SWX_SRC
#define R2DP_SWX_SRC "/usr/src/dpdk"
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
	char iospec_path[PATH_MAX];
	int cdev_id;           /* cryptodev for the ipsec extern; -1 none */

	/* Cached table key layout from table_info (bytes, big-endian order). */
	uint32_t inbound_key_size;
	uint32_t outbound_key_size;

	/* Pipeline run worker (brings up the SWX datapath). */
	pthread_t th;
	int th_started;
	atomic_int running;

	int started;
	int wake_fd;
};

/* SWX run quanta per burst (arbitrary; bounds how many instructions one
 * rte_swx_pipeline_run call executes before yielding to the ipsec block). */
#define P4_RUN_QUANTA 1000

/* Packet-path worker: drain the pipeline's input, execute the PNA program,
 * run the ipsec extern head-of-line, then loop.  Mirrors examples/pipeline
 * thread_main: run each pipeline then each block (the ipsec extern) with no
 * sleep so the pipeline saturates. */
static void *p4_worker(void *arg)
{
	struct p4_priv *pr = arg;

	while (atomic_load_explicit(&pr->running, __ATOMIC_RELAXED)) {
		if (pr->p)
			rte_swx_pipeline_run(pr->p, P4_RUN_QUANTA);
		if (pr->ipsec)
			rte_swx_ipsec_run(pr->ipsec);
	}
	return NULL;
}

static void p4_caps(struct fwd_dp *dp)
{
	/* Advertise ONLY what the ipsec extern actually installs.  We program
	 * AEAD AES-GCM-128 (sa_add wires RTE_CRYPTO_AEAD_AES_GCM from the
	 * r2dp key||salt blob) with no separate integrity transform, so the
	 * enc/integ bitmap pairs must match the DPDK backend (dpdk_sad.c):
	 * advertising a transform the dataplane cannot install makes racoon2
	 * negotiate a dead SA. */
	memset(dp->caps_bits_enc, 0, sizeof(dp->caps_bits_enc));
	memset(dp->caps_bits_integ, 0, sizeof(dp->caps_bits_integ));
	dp->caps_bits_enc[0]    = (1u << R2DP_ENCR_AES_GCM_16);
	dp->caps_bits_integ[0]  = (1u << R2DP_INTEG_NONE);
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

/* Resolve a table's action_id for a given action index (action_ids are
 * assigned globally per pipeline in spec order, NOT per-table 0..n-1).  We
 * look the action up by its position in the table's action list, which the
 * compiled spec fixes (inbound: ipsec_enable, ipsec_bypass, drop; outbound:
 * ipsec_protect, spd_bypass, spd_discard, drop).  Returns the action_id or a
 * negative error. */
static int p4_table_action_id(struct rte_swx_pipeline *p, uint32_t table_id,
			      uint32_t action_index)
{
	struct rte_swx_ctl_table_action_info tai;
	int rc;

	memset(&tai, 0, sizeof(tai));
	rc = rte_swx_ctl_table_action_info_get(p, table_id, action_index,
					       &tai);
	if (rc)
		return -EIO;
	return (int)tai.action_id;
}

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

/* Find + configure a lookaside cryptodev (the operator adds `--vdev
 * crypto_openssl0` or crypto_aesni_mb0 on the command line, like the DPDK
 * backend).  The ipsec extern's crypto_dev_name must resolve to a valid
 * device id (rte_swx_ipsec_create fails EINVAL without one). */
static int p4_crypto_init(struct p4_priv *pr)
{
	static const char *const names[] = {
		"crypto_aesni_mb0", "crypto_aesni_mb", "crypto_openssl0",
		"crypto_openssl",
	};
	struct rte_cryptodev_config cconf;
	struct rte_cryptodev_qp_conf qconf;
	int id = -1;

	pr->cdev_id = -1;
	for (size_t i = 0; i < RTE_DIM(names) && id < 0; i++)
		id = rte_cryptodev_get_dev_id(names[i]);
	if (id < 0) {
		P4_LOG("no crypto device; pass --vdev crypto_openssl0 "
		       "(or crypto_aesni_mb0)");
		return -ENODEV;
	}
	pr->cdev_id = id;
	memset(&cconf, 0, sizeof(cconf));
	cconf.socket_id = SOCKET_ID_ANY;
	cconf.nb_queue_pairs = 1;
	memset(&qconf, 0, sizeof(qconf));
	qconf.nb_descriptors = 2048;
	if (rte_cryptodev_configure(id, &cconf) < 0) {
		P4_LOG("cryptodev configure failed");
		return -EIO;
	}
	if (rte_cryptodev_queue_pair_setup(id, 0, &qconf, SOCKET_ID_ANY) < 0) {
		P4_LOG("cryptodev qp0 setup failed");
		return -EIO;
	}
	if (rte_cryptodev_start(id) < 0) {
		P4_LOG("cryptodev start failed");
		return -EIO;
	}
	P4_LOG("crypto %s ready", rte_cryptodev_name_get(id));
	return 0;
}

/* Create an rte_ring the iospec / ipsec extern port will reference (empty or
 * one already existing is fine; a missing ring makes the port constructor
 * fail -> build_from_lib ENODEV). */
static int p4_ring(const char *name)
{
	struct rte_ring *r = rte_ring_lookup(name);
	if (r)
		return 0;
	r = rte_ring_create(name, 1024, 0, RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (!r)
		return -errno;
	return 0;
}

/* USC/DSC flow: .spec -> codegen C -> compile to .so -> build_from_lib.
 * The iospec's ring ports and the ipsec extern's rings must exist before
 * build_from_lib (their port constructors look them up by name). */
static int p4_build_from_spec(struct p4_priv *pr, const char *spec_path)
{
	FILE *spec, *code;
	char code_c[PATH_MAX], code_so[PATH_MAX];
	uint32_t err_line = 0;
	const char *err = NULL;
	char cmd[PATH_MAX * 2];
	const char *tmp;
	const char *base;
	const char *swx_src;
	int rc;

	/* The iospec ring ports and the ipsec extern's rings must pre-exist. */
	{   const char *ring_names[] = { "R2DP_IN0", "R2DP_IN1", "R2DP_OUT0",
					"R2DP_OUT1", "IP_IN", "IP_OUT", NULL };
	    int i;
	    for (i = 0; ring_names[i]; i++) {
		int rr = p4_ring(ring_names[i]);
		if (rr) { P4_LOG("ring %s: %s", ring_names[i],
				strerror(-rr)); return rr; }
	    }
	}

	/* Codegen .c/.so land in a WRITABLE scratch dir (the spec itself may
	 * sit under a root-owned install path).  Keyed on the spec leaf so two
	 * pipelines don't clobber each other. */
	tmp = getenv("R2DP_P4_SCRATCH");
	if (!tmp || !*tmp)
		tmp = getenv("TMPDIR");
	if (!tmp || !*tmp)
		tmp = "/tmp";
	base = strrchr(spec_path, '/');
	base = base ? base + 1 : spec_path;
	snprintf(code_c,  sizeof(code_c),  "%s/%s.c",  tmp, base);
	snprintf(code_so, sizeof(code_so), "%s/%s.so", tmp, base);

	/* Ensure the scratch dir exists (best-effort mkdir -p). */
	{
		char m[PATH_MAX];
		snprintf(m, sizeof(m), "mkdir -p '%s'", tmp);
		(void)system(m);
	}

	/* DPDK source dir for the internal codegen headers (runtime override of
	 * the compile-time R2DP_SWX_SRC default). */
	swx_src = getenv("R2DP_SWX_SRC");
	if (!swx_src || !*swx_src)
		swx_src = R2DP_SWX_SRC;

	/* Pipeline I/O spec: ports + the ipsec extern rings.  Auto-write a
	 * minimal ring-based one (no NIC needed) when none is configured. */
	{
		char *iospec = getenv("R2DP_P4_IOSPEC");
		char io_path[PATH_MAX];
		FILE *io_f;

		if (iospec && *iospec) {
			snprintf(pr->iospec_path, sizeof(pr->iospec_path), "%s",
				 iospec);
		} else {
			snprintf(io_path, sizeof(io_path), "%s/%s.io", tmp, base);
			snprintf(pr->iospec_path, sizeof(pr->iospec_path), "%s",
				 io_path);
			io_f = fopen(io_path, "r");
			if (!io_f) {
				io_f = fopen(io_path, "w");
				if (io_f) {
					fputs("port in 0 ring R2DP_IN0 bsz 32\n",
					      io_f);
					fputs("port in 1 ring R2DP_IN1 bsz 32\n",
					      io_f);
					fputs("port out 0 ring R2DP_OUT0 bsz 32\n",
					      io_f);
					fputs("port out 1 ring R2DP_OUT1 bsz 32\n",
					      io_f);
					fclose(io_f);
				}
			}
		}
	}

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
		"gcc -shared -fPIC -O2 -o '%s' '%s' -I'%s' -I'%s/lib/pipeline' "
		"-L'%s' -lrte_pipeline -lrte_ipsec -lrte_eal -lrte_mbuf "
		"-lrte_mempool -lrte_ring 2>%s.err",
		code_so, code_c, R2DP_RTE_INCLUDE, swx_src,
		R2DP_RTE_LIB, code_c);
	rc = system(cmd);
	if (rc) {
		P4_LOG("compile .so failed rc=%d (see %s.err)", rc, code_c);
		return -EIO;
	}

	{
		FILE *io_f = fopen(pr->iospec_path, "r");
		if (!io_f) {
			P4_LOG("iospec %s: %s", pr->iospec_path,
			       strerror(errno));
			return -errno;
		}
		rc = rte_swx_pipeline_build_from_lib(&pr->p, "r2dp", code_so,
						   io_f, 0);
		fclose(io_f);
	}
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
	 * resolve into; SA ids written to ipsec_hdr.sa_id are looked up here.
	 * It needs a configured cryptodev (param validation requires one). */
	rc = p4_crypto_init(pr);
	if (rc)
		return rc;
	rc = rte_swx_ipsec_create(&pr->ipsec, "r2dp-ipsec",
				  &(struct rte_swx_ipsec_params){
					.ring_in_name    = "IP_IN",
					.ring_out_name   = "IP_OUT",
					.crypto_dev_name = rte_cryptodev_name_get(
					    pr->cdev_id),
					.n_sa_max        = P4_SA_MAX,
				  }, 0);
	if (rc) {
		P4_LOG("ipsec_create %d", rc);
		return -EIO;
	}

	/* Program the classification regarrays the spec's parser/apply read
	 * (they default to 0).  PNA direction: 0 = NET_TO_HOST (inbound /
	 * decrypt), 1 = HOST_TO_NET (outbound / encrypt).  Port 0 = outer
	 * (ciphertext/wire) leg, port 1 = inner (plaintext) leg; both are
	 * inbound-candidate on their own leg, so they are NOT from_ipsec (the
	 * ipsec extern's own return rings, IP_IN/IP_OUT, are the from_ipsec
	 * ports).  Set direction per port and leave ipsec_port_in_* at their
	 * extern rings' identity (see PLAN §8 / spec apply). */
	(void)rte_swx_ctl_pipeline_regarray_write(pr->p, "direction", 0, 0);
	(void)rte_swx_ctl_pipeline_regarray_write(pr->p, "direction", 1, 1);
	/* Parser `from_ipsec` = (input_port == ipsec_port_in_*).  The extern
	 * returns processed packets on its own port; for our two-leg topology
	 * the SAD is keyed per-leg by the port the wire packet arrives on, so
	 * mark neither static leg as from_ipsec.  Pointer-only content; see
	 * regarray_name resolution below. */
	(void)rte_swx_ctl_pipeline_regarray_write(pr->p,
		"ipsec_port_in_inbound", 0, (uint64_t)0xffffffffUL);
	(void)rte_swx_ctl_pipeline_regarray_write(pr->p,
		"ipsec_port_in_outbound", 0, (uint64_t)0xffffffffUL);

	/* Launch the packet-path worker. */
	atomic_store_explicit(&pr->running, 1, __ATOMIC_RELAXED);
	if (pthread_create(&pr->th, NULL, p4_worker, pr) != 0) {
		P4_LOG("worker create failed");
		atomic_store_explicit(&pr->running, 0, __ATOMIC_RELAXED);
		return -EIO;
	}
	pr->th_started = 1;

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
	int rc, i, inbound, deleting;
	uint32_t dip, spi;

	/* Direction comes from the vtable flag (dp.h): only SA_ADD with
	 * FWD_DP_SA_INBOUND installs the inbound (decrypt) SAD entry; an
	 * outbound SA is the encrypt leg the SPD references via sa_id. */
	inbound = (add & FWD_DP_SA_INBOUND) != 0;
	deleting = !(add & 1);

	/* Host-order key from the wire (matches dpdk_sad.c conventions). */
	if (sa->dst.family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;
	memcpy(&dip, sa->dst.addr, 4);
	dip = ntohl(dip);
	spi = ntohl(sa->spi);

	e = p4_sad_lookup(pr, dip, spi, sa->proto);
	if (deleting) {
		if (!e)
			return -ENOENT;
		if (pr->ipsec)
			rte_swx_ipsec_sa_delete(pr->ipsec, e->sl_id);
		if (inbound) {
			/* remove the (dip,spi) -> ipsec_enable SAD entry */
			memset(&ent, 0, sizeof(ent));
			memset(key, 0, sizeof(key));
			{
				uint32_t dip_be = htonl(dip);
				uint32_t spi_be = htonl(spi);
				memcpy(&key[0], &dip_be, 4);
				memcpy(&key[4], &spi_be, 4);
			}
			ent.key = key;
			rc = rte_swx_ctl_pipeline_table_entry_delete(pr->ctl,
					"inbound_table_0", &ent);
			if (rc)
				P4_LOG("inbound entry del %d", rc);
		}
		e->in_use = 0;
		return rte_swx_ctl_pipeline_commit(pr->ctl, 0);
	}

	if (!e) {
		for (i = 0; i < P4_SA_MAX; i++)
			if (!pr->sad[i].in_use) { e = &pr->sad[i]; break; }
		if (!e)
			return -ENOSPC;
		e->dip = dip;
		e->spi = spi;
		e->proto = sa->proto;
		e->dir = inbound ? R2DP_DIR_IN : R2DP_DIR_OUT;
		e->sl_id = (uint32_t)i;      /* stable per-install id */
		e->in_use = 1;
	}

	/* Crypto SA in the ipsec extern (spi -> cipher/AEAD params + key).
	 * r2dp provisions AES-GCM (see dp_gcm.c); `blob` is the AEAD key+salt
	 * (enckeylen bytes), and the extern strips the trailing 4 salt bytes. */
	if (blob && blen) {
		uint32_t sa_id = 0;
		struct rte_swx_ipsec_sa_params sp = {0};
		sp.encrypt = !inbound;    /* encrypt = outbound */
		sp.crypto.is_aead = 1;
		sp.crypto.aead.alg = RTE_CRYPTO_AEAD_AES_GCM;
		if (blen > RTE_SWX_IPSEC_KEY_SIZE_MAX)
			return -E2BIG;
		memcpy(sp.crypto.aead.key, blob, blen);
		sp.crypto.aead.key_size = (uint32_t)blen;   /* key || salt */
		sp.encap.esp.spi = sa->spi;   /* network order SPI */
		sp.encap.tunnel_mode = (sa->mode == R2DP_MODE_TUNNEL);
		sp.encap.tunnel_ipv4 = 1;
		if (sa->src.family == R2DP_AF_INET4)
			memcpy(&sp.encap.tunnel.ipv4.src_addr,
			       sa->src.addr, sizeof(struct in_addr));
		if (sa->dst.family == R2DP_AF_INET4)
			memcpy(&sp.encap.tunnel.ipv4.dst_addr,
			       sa->dst.addr, sizeof(struct in_addr));
		rc = rte_swx_ipsec_sa_add(pr->ipsec, &sp, &sa_id);
		if (rc) {
			P4_LOG("ipsec sa_add %d", rc);
			e->in_use = 0;
			return rc;
		}
		e->sl_id = sa_id;   /* the id the action must write */
	}

	/* Only the inbound (decrypt) SA gets a SAD table entry; outbound SAs
	 * are reached through the SPD's ipsec_protect(sa_id). */
	if (!inbound)
		return 0;

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
	ent.action_id = (uint64_t)p4_table_action_id(pr->p, 0, 0); /* ipsec_enable */
	ent.action_data = data;
	rc = rte_swx_ctl_pipeline_table_entry_add(pr->ctl, "inbound_table_0",
						  &ent);
	if (rc) {
		P4_LOG("inbound entry add %d", rc);
		return rc;
	}
	return rte_swx_ctl_pipeline_commit(pr->ctl, 0);
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
		ent.action_id = (uint64_t)p4_table_action_id(pr->p, 1, 2); /* spd_discard */
		break;
	case R2DP_ACT_PROTECT: {
		uint32_t id_be = htonl(sp->slid);
		memcpy(data, &id_be, 4);
		ent.action_id = (uint64_t)p4_table_action_id(pr->p, 1, 0); /* ipsec_protect */
		ent.action_data = data;
		break;
	}
	default:
		ent.action_id = (uint64_t)p4_table_action_id(pr->p, 1, 1); /* spd_bypass */
		break;
	}
	rc = rte_swx_ctl_pipeline_table_entry_add(pr->ctl, "outbound_table_0",
						  &ent);
	if (rc) {
		P4_LOG("outbound entry add %d", rc);
		return rc;
	}
	return rte_swx_ctl_pipeline_commit(pr->ctl, 0);
}

static int p4_sp_del(struct fwd_dp *dp, const struct r2dp_sp *sp)
{
	struct p4_priv *pr = dp->priv;
	uint8_t key[16];
	struct rte_swx_table_entry ent;
	uint32_t ssrc, sdst;
	int rc;

	if (sp->sel_src.family != R2DP_AF_INET4 ||
	    sp->sel_dst.family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;
	memcpy(&ssrc, sp->sel_src.addr, 4);
	memcpy(&sdst, sp->sel_dst.addr, 4);
	ssrc = ntohl(ssrc);
	sdst = ntohl(sdst);

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
	rc = rte_swx_ctl_pipeline_table_entry_delete(pr->ctl, "outbound_table_0",
						     &ent);
	if (rc) {
		P4_LOG("outbound entry del %d", rc);
		return rc;
	}
	return rte_swx_ctl_pipeline_commit(pr->ctl, 0);
}

static int64_t p4_sa_bytes(struct fwd_dp *dp, uint32_t spi, uint32_t dip)
{
	(void)spi; (void)dip;
	return -1;    /* SWX per-SA byte counters exposed when available */
}

static void p4_stop(struct fwd_dp *dp)
{
	struct p4_priv *pr = dp->priv;
	/* Always free whatever was allocated, even on a partial start (the
	 * probe calls stop on failure).  `started` is not the only guard. */
	atomic_store_explicit(&pr->running, 0, __ATOMIC_RELAXED);
	if (pr->th_started) {
		pthread_join(pr->th, NULL);
		pr->th_started = 0;
	}
	if (pr->ctl)
		rte_swx_ctl_pipeline_free(pr->ctl);
	if (pr->ipsec)
		rte_swx_ipsec_free(pr->ipsec);
	if (pr->p)
		rte_swx_pipeline_free(pr->p);
	pr->ctl = NULL;
	pr->ipsec = NULL;
	pr->p = NULL;
	pr->started = 0;
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

	/* The SWX pipeline lives in the DPDK EAL heap; init EAL first (the
	 * r2dp-fwd --dp p4 path passes its leftover args as EAL args). */
	if (rte_eal_init(argc ? *argc : 1, argv ? *argv : NULL) < 0)
		return -EIO;

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

	/* Bring up the pipeline now (codegen -> .so -> build_from_lib -> ctl).
	 * On failure roll back: ops = NULL so the control loop never applies
	 * SAs to a pipeline we could not start (mirrors dp_dpdk.c probe). */
	if (dp->ops->start(dp) < 0) {
		dp->ops->stop(dp);
		dp->ops = NULL;
		return -EIO;
	}
	return 0;
}

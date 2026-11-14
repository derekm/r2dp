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
#include <sched.h>
#include <rte_ring.h>
#include <rte_cryptodev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

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

/* Max P4 pipeline slices (cores) this binary can run.  Compiled in so the
 * per-slice arrays are fixed (no malloc'd VLA of icky structs); default 8.
 * R2DP_P4_WORKERS at runtime selects how many are actually started. */
#ifndef R2DP_P4_MAX_INST
#define R2DP_P4_MAX_INST 8
#endif

#define P4_LOG(fmt, ...) \
	fprintf(stderr, "r2dp-fwd: p4: " fmt "\n", ##__VA_ARGS__)

#define P4_SA_MAX 1024
#define P4_SP_MAX 1024

struct p4_sa {
	uint32_t spi;        /* host order */
	uint32_t sip;        /* host order tunnel src */
	uint32_t dip;        /* host order tunnel dst */
	uint32_t sl_id[R2DP_P4_MAX_INST]; /* per-slice cryptodev SA id: each
					  * slice's ipsec extern allocates its
					  * own SA id, so a logical SA maps to
					  * one id per slice */
	uint64_t gen;        /* install generation (higher = newer) */
	int in_use;
	uint8_t proto;
	uint8_t dir;
};

/* SPD policy mirror (keyed by selector): the control plane may install an OUT
 * PROTECT policy BEFORE its egress SA exists (spmd loads SPD at startup, then
 * GETSPI/SA_ADD), so sp_add must NOT refuse.  We keep the policy here and
 * (re)program outbound_table_0 from sa_add/sa_del as SAs bind/unbind. */
struct p4_pol {
	int in_use;
	struct r2dp_sp sp;               /* full policy (selector, tunnel) */
	uint32_t bound_sl_id;            /* bound egress crypto id; UINT32_MAX */
};

/* A P4 data-plane "slice" (NIC pipeline stage): one complete copy of the PNA
 * program -- its own rte_swx_pipeline, its own ctl handle, its own ipsec
 * extern (own cryptodev queue pair), and its own bounded rings.  A slice is
 * single-owner (rte_swx_* is not threaded), exactly like one P4 pipeline
 * stage on a NIC.  N slices run on N cores; R2DP_P4_WORKERS sets N (default 1
 * = the historical single-pipeline layout, byte-for-byte). */
struct p4_priv;

struct p4_inst {
	struct p4_priv *priv;            /* back-pointer to the owner */
	unsigned s;                       /* this slice's index (0..n_inst-1) */
	struct rte_swx_pipeline *p;
	struct rte_swx_ctl_pipeline *ctl;
	struct rte_swx_ipsec *ipsec;
	uint8_t cdev_qp;                 /* this slice's cryptodev queue pair */

	/* Bounded rings bridging the ethdev legs to this slice's pipeline
	 * (names are per-slice-suffixed: R2DP_IN0_<i>, IP_IN_<i>, ...). */
	struct rte_ring *in0, *in1, *out0, *out1;

	/* Slice run worker. */
	pthread_t th;
	int th_started;
	atomic_int running;

	/* RX/egress packet counters (set by the I/O thread, read by SIGUSR1 dump). */
	unsigned long c_outer, c_inner, c_out0, c_out1;

	/* Resolved pipeline table IDs (by name at bring-up).  p4c-dpdk emits the
	 * tables in its own order (not source order), so hard-coded IDs are
	 * wrong the moment a table is added or the source is reordered.  Resolve
	 * each by name once per slice; every control-plane op uses these. */
	uint32_t tid_inbt;   /* inbound_table_0   (SAD)            */
	uint32_t tid_outbt;  /* outbound_table_0  (outbound SPD)   */
	uint32_t tid_routing;/* routing_table_0   (LPM)            */
	uint32_t tid_nhop;   /* next_hop_table_0  (egress)         */
	uint32_t tid_inspd;  /* inbound_spd_table_0 (RFC 4301 drop) */
};

struct p4_priv {
	uint32_t n_inst;                     /* number of slices (>=1) */
	struct p4_inst inst[R2DP_P4_MAX_INST];
	struct p4_sa sad[P4_SA_MAX];
	struct p4_pol spd[P4_SP_MAX];
	uint64_t gen;                       /* next p4_sa install generation */
	char *spec_path;
	char iospec_path[PATH_MAX];
	int cdev_id;           /* cryptodev for the ipsec extern; -1 none */

	/* I/O legs: outer = ciphertext/wire side, inner = plaintext side.
	 * Each maps an ethdev port to a pipeline input ring and an output
	 * ring (see the iospec / port_in_* names).  Shared across slices: the
	 * single I/O thread hashes each RX frame to one slice's input rings
	 * (per-flow affinity) and drains every slice's egress to TX -- so each
	 * ethdev queue has ONE consumer (RX) and ONE producer (TX). */
	int outer_port, inner_port;
	struct rte_mempool *pool;
	/* Inner (plaintext) tap's own MAC, read at io_init and programmed into
	 * the inner next-hop entry so a decrypted frame is delivered unicast to
	 * the inner host's kernel (which drops dst 00:00:00:00:00:00).  Mirrors
	 * dp_dpdk.c our_inner_mac. */
	uint8_t our_inner_mac[RTE_ETHER_ADDR_LEN];

	/* Cached table key layout from table_info (bytes, big-endian order). */
	uint32_t inbound_key_size;
	uint32_t outbound_key_size;

	int started;
	int wake_fd;
	/* Single RX distributor thread for the live path (hashes eth RX to
	 * per-slice input rings).  NULL/unset under R2DP_P4_BENCH (bench
	 * workers self-inject). */
	pthread_t rx_th;
	int rx_started;
};

/* I/O bridge burst size. */
#define P4_BURST_SZ 32
#define P4_POOL_SIZE 8192
#define P4_POOL_CACHE 256

/* SWX run quanta per burst (arbitrary; bounds how many instructions one
 * rte_swx_pipeline_run call executes before yielding to the ipsec block). */
#define P4_RUN_QUANTA 1000

static void p4_stats_on_req(struct p4_priv *p);
static void *p4_bench_worker(void *arg);

/* Pin a slice worker to its own CPU core so N pipelines run on N cores
 * (deterministic, not probabilistic scheduling -- a requirement for the
 * multicore sweep and for later SmartNIC/ASIC affinity models).  Slice s
 * pins to CPU s; on boxes with fewer than n_inst cores the OS falls back
 * to co-scheduling rather than failing. */
static void p4_pin(unsigned s)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(s % CPU_SETSIZE, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0)
		P4_LOG("slice %u: sched_setaffinity failed", s);
}

/* Per-slice data-plane worker: run THIS slice's pipeline + ipsec extern.
 * The ethdev legs (RX distributor + TX) are owned by the single p4_io_worker
 * thread, so per-slice workers never touch rte_eth_* directly (an ethdev
 * queue is not multi-producer/multi-consumer).  Mirrors examples/pipeline
 * thread_main: run each pipeline then each block (the ipsec extern) with no
 * sleep so the pipeline saturates. */
static void *p4_worker(void *arg)
{
	struct p4_inst *it = arg;
	struct p4_priv *pr = it->priv;
	p4_pin(it->s);
	unsigned s = it->s;
	uint64_t last_dump = 0;

	while (atomic_load_explicit(&it->running, __ATOMIC_RELAXED)) {
		/* Both ethdev legs are owned by the single p4_io_worker
		 * (RX distributor + TX), so the RX queue is a single consumer
		 * and the TX queue a single producer -- a DPDK ethdev queue is
		 * single-producer, so N per-slice workers must NOT each call
		 * rte_eth_tx_burst on queue 0.  This per-slice worker only runs
		 * the pipeline + ipsec extern, then the io worker drains the
		 * slice's egress rings to the NIC. */

		/* Run the pipeline + ipsec extern. */
		if (it->p)
			rte_swx_pipeline_run(it->p, P4_RUN_QUANTA);
		/* rte_swx_pipeline_run only DOES work; ring output ports buffer
		 * to bsz and only enqueue on a full batch or an explicit
		 * rte_swx_pipeline_flush().  A lone live frame (sparse peer,
		 * 1 pkt per round trip) never fills a 32-batch, so flush after
		 * every run or it silently never leaves the pipeline. */
		if (it->p)
			rte_swx_pipeline_flush(it->p);
		if (it->ipsec)
			rte_swx_ipsec_run(it->ipsec);

		/* Periodic activity dump (every ~1s) so ingress/egress is
		 * visible even with no signal handler wired. */
		if (fwd_stats_req)
			p4_stats_on_req(pr);
		if (rte_get_tsc_cycles() - last_dump > rte_get_tsc_hz()) {
			uint32_t q0 = rte_ring_count(it->in0);
			uint32_t q1 = rte_ring_count(it->in1);
			uint32_t qo0 = rte_ring_count(it->out0);
			uint32_t qo1 = rte_ring_count(it->out1);
			struct rte_swx_table_stats ts1;
			uint64_t act1[16];
			char ipn[64], ipon[64];
			struct rte_ring *ipin, *ipout;
			snprintf(ipn, sizeof(ipn), s ? "IP_IN_%u" : "IP_IN", s);
			snprintf(ipon, sizeof(ipon), s ? "IP_OUT_%u" : "IP_OUT", s);
			ipin  = rte_ring_lookup(ipn);
			ipout = rte_ring_lookup(ipon);
			uint32_t qi = ipin ? rte_ring_count(ipin) : 0;
			uint32_t qo = ipout ? rte_ring_count(ipout) : 0;
			struct rte_cryptodev_stats cst;
			if (pr->cdev_id >= 0 &&
			    rte_cryptodev_stats_get(pr->cdev_id, &cst) == 0)
				P4_LOG("crypto: enq=%llu deq=%llu enq_err=%llu",
				       (unsigned long long)cst.enqueued_count,
				       (unsigned long long)cst.dequeued_count,
				       (unsigned long long)cst.enqueue_err_count);
			memset(&ts1, 0, sizeof(ts1));
			ts1.n_pkts_action = act1;
			{
				struct rte_swx_table_stats ibs;
				uint64_t iba[16];
				memset(&ibs, 0, sizeof(ibs));
				ibs.n_pkts_action = iba;
				if (rte_swx_ctl_pipeline_table_stats_read(it->p,
					 "inbound_table_0", &ibs) == 0)
					P4_LOG("ib: hit=%llu miss=%llu a0=%llu a1=%llu",
					       (unsigned long long)ibs.n_pkts_hit,
					       (unsigned long long)ibs.n_pkts_miss,
					       (unsigned long long)iba[0],
					       (unsigned long long)iba[1]);
			}
			if (rte_swx_ctl_pipeline_table_stats_read(it->p,
				 "outbound_table_0", &ts1) == 0)
				P4_LOG("pkt: out_rx=%lu in_rx=%lu out0=%lu out1=%lu "
				       "| rings in0=%u in1=%u out0r=%u out1r=%u "
				       "| ipsec ipin=%u ipout=%u "
				       "| ob_hit=%llu ob_miss=%llu "
				       "| act a5=%llu a6=%llu a7=%llu",
				       it->c_outer, it->c_inner, it->c_out0,
				       it->c_out1, q0, q1, qo0, qo1, qi, qo,
				       (unsigned long long)ts1.n_pkts_hit,
				       (unsigned long long)ts1.n_pkts_miss,
				       (unsigned long long)act1[5],
				       (unsigned long long)act1[6],
				       (unsigned long long)act1[7]);
			else
				P4_LOG("pkt: out_rx=%lu in_rx=%lu out0=%lu out1=%lu "
				       "| rings in0=%u in1=%u out0r=%u out1r=%u",
				       it->c_outer, it->c_inner, it->c_out0,
				       it->c_out1, q0, q1, qo0, qo1);
			last_dump = rte_get_tsc_cycles();
		}
	}
	return NULL;
}

/*
 * Flow hash -> slice index for the LIVE path.  The NIC hands each
 * pipeline a subset of flows (RSS); here a single RX thread emulates that:
 * every frame of one flow/SA must land on ONE slice so the extern's per-SA
 * state (CSP replay window, SA crypto) lives on a single core.
 *
 * Affinity keys:
 *  - ESP (proto 50): outer IPv4 src + dst.  Do NOT pin on SPI: only the
 *    FIRST fragment carries the ESP header/SPI, so a (dst, spi) hash would
 *    scatter one SA's fragments across slices.  src+dst is fragment-invariant
 *    and keeps an entire SA (incl. all its fragments) on one slice, so the
 *    extern's per-SA state (CSP replay window, SA crypto) stays on one core.
 *  - Everything else: (proto, src, dst, sport, dport) 5-tuple.
 * Returns 0..n_inst-1; must be stable across relaunch (fixed seed = xor
 * fold, no randomness).  For n_inst<=1 returns slice 0 without hashing.
 */
static uint32_t p4_xor(const uint8_t *p, size_t n)
{
	uint32_t h = 0x9e3779b9;
	size_t i;
	for (i = 0; i < n; i++) {
		h ^= p[i];
		h *= 0x85ebca6b;
		h ^= h >> 13;
	}
	return h;
}

static uint32_t p4_flow_slice(struct p4_priv *pr, const struct rte_mbuf *m)
{
	uint8_t bb[16];
	size_t n = 0;
	const uint8_t *d = rte_pktmbuf_mtod(m, const uint8_t *);
	uint16_t l = rte_pktmbuf_pkt_len(m);

	if (pr->n_inst <= 1)
		return 0;   /* one slice: everything lands on it */

	/* Ethernet (14B) + IPv4 (20B).  Requires ethertype 0x0800. */
	if (l < 14 + 20)
		return p4_xor(d, l) % pr->n_inst;
	if (d[12] != 0x08 || d[13] != 0x00)
		return p4_xor(d, l) % pr->n_inst;
	{
		const uint8_t *ip = d + 14;
		uint8_t proto = ip[9];
		/* IPv4 fragment flags/offset (bytes 6-8): offset (8-byte units) is
		 * the low 13 bits; MF (more-fragments) is bit 14 of byte 6.
		 * A NON-FIRST fragment carries NO transport header (no UDP dport,
		 * no ESP header), so ports/SPI are unreadable there -- hash it on
		 * the fragment-invariant (proto, src, dst) so every fragment of one
		 * datagram stays on the same slice as the first. */
		uint16_t frag = ((uint16_t)ip[6] << 8) | ip[7];
		int mf =     (frag >> 13) & 1;   /* more-fragments */
		uint16_t fo = frag & 0x1fff;     /* fragment offset (8-byte units) */
		if (proto == 50) {
			/* ESP: pin on the outer IP flow (src, dst) -- NOT
			 * (dst + SPI).  Fragments arrive as separate outer
			 * IP packets and only the FIRST carries the ESP
			 * header/SPI; a non-first fragment has no SPI at
			 * ip+20, so a (dst,SPI) hash would scatter one SA's
			 * fragments across slices.  All fragments of one SA
			 * must land on one slice (reassembly + per-SA replay
			 * are per-slice and single-owner), so hash every ESP
			 * frame on the fragment-invariant outer src+dst. */
			memcpy(bb, ip + 12, 4);          /* src */
			memcpy(bb + 4, ip + 16, 4);      /* dst */
			n = 8;
		} else if (proto == 17 && fo == 0 && !mf && l >= 14 + 20 + 8 &&
			   ip[22] == 0x11 && ip[23] == 0x94) {
			/* ESP-in-UDP (RFC 3948): proto 17, unfragmented FIRST
			 * frame, UDP dst port 4500 (0x1194).  The parser
			 * (nat_demux) treats this as ESP when the first 32
			 * bits after UDP are a non-zero SPI, so it carries
			 * per-SA state in the extern -- hash it like ESP on
			 * (src,dst) so the same SA's ESP-in-UDP and its
			 * fragments stay on one slice. */
			memcpy(bb, ip + 12, 4);          /* src */
			memcpy(bb + 4, ip + 16, 4);      /* dst */
			n = 8;
		} else if (fo != 0 || mf) {
			/* Non-first fragment (any proto): no transport header.  Hash on
			 * (proto, src, dst) so all fragments of one datagram -- incl. a
			 * fragmented ESP-in-UDP flow, whose first fragment hashes
			 * (src,dst) above -- land on the same slice as the first. */
			bb[0]=ip[12]; bb[1]=ip[13]; bb[2]=ip[14]; bb[3]=ip[15];
			bb[4]=proto;
			memcpy(bb + 5, ip + 16, 4);
			n = 9;
		} else if (l >= 14 + 20 + 8) {  /* 5-tuple incl. TCP/UDP */
			/* src(4) proto(1) dst(4) sport(2) dport(2) = 13B */
			bb[0]=ip[12]; bb[1]=ip[13]; bb[2]=ip[14]; bb[3]=ip[15];
			bb[4]=proto;
			bb[5]=ip[16]; bb[6]=ip[17]; bb[7]=ip[18]; bb[8]=ip[19];
			bb[9]=ip[20]; bb[10]=ip[21]; bb[11]=ip[22]; bb[12]=ip[23];
			n = 13;
		} else {
			/* raw IP: (proto, src, dst) */
			memcpy(bb, ip + 12, 4); bb[4]=proto;
			memcpy(bb + 5, ip + 16, 4); n = 9;
		}
	}
	return p4_xor(bb, n) % pr->n_inst;
}

/*
 * Live-path RX distributor: ONE thread reads both ethdev legs and hashes
 * every frame to a slice's input ring (R2DP_IN0_<i> outer, R2DP_IN1_<i>
 * inner).  One thread only, so the ethdev RX queue is a single consumer
 * (no two workers racing rte_eth_rx_burst on the same queue) -- exactly
 * like a NIC RX engine fanning flows out to N pipelines.  The per-slice
 * workers (p4_worker) then only run pipeline+extern and TX.
 */
static void *p4_io_worker(void *arg)
{
	struct p4_priv *pr = arg;

	while (atomic_load_explicit(&pr->inst[0].running, __ATOMIC_RELAXED)) {
		/* RX: one thread drains both legs and fans frames out to
		 * slices, so each RX queue is a single consumer. */
		if (pr->outer_port >= 0) {
			struct rte_mbuf *pkts[P4_BURST_SZ];
			uint16_t n = rte_eth_rx_burst(pr->outer_port, 0,
						     pkts, P4_BURST_SZ);
			uint16_t k;
			for (k = 0; k < n; k++) {
				uint32_t s = p4_flow_slice(pr, pkts[k]);
				pr->inst[s].c_outer++;
				/* ring full: drop (fail-closed, no copy) */
				if (rte_ring_enqueue(pr->inst[s].in0,
						     pkts[k]) != 0)
					rte_pktmbuf_free(pkts[k]);
			}
		}
		if (pr->inner_port >= 0) {
			struct rte_mbuf *pkts[P4_BURST_SZ];
			uint16_t n = rte_eth_rx_burst(pr->inner_port, 0,
						     pkts, P4_BURST_SZ);
			uint16_t k;
			for (k = 0; k < n; k++) {
				uint32_t s = p4_flow_slice(pr, pkts[k]);
				pr->inst[s].c_inner++;
				if (rte_ring_enqueue(pr->inst[s].in1,
						     pkts[k]) != 0)
					rte_pktmbuf_free(pkts[k]);
			}
		}

		/* TX: drain EVERY slice's egress rings to the ethdev.  One
		 * thread owns the TX queues (single producer), so N workers
		 * never call rte_eth_tx_burst on queue 0 concurrently (that
		 * is a DPDK data race).  Count with the tx_burst RETURN (not
		 * the dequeue count: an unsent mbuf is a leak, and a full TX
		 * queue must not be counted as transmitted). */
		if (pr->outer_port >= 0) {
			unsigned s;
			for (s = 0; s < pr->n_inst; s++) {
				if (!pr->inst[s].out0)
					continue;   /* ring lookup failed at start */
				struct rte_mbuf *pkts[P4_BURST_SZ];
				uint16_t n = rte_ring_dequeue_burst(
					pr->inst[s].out0, (void **)pkts,
					P4_BURST_SZ, NULL), k, tx;
				if (!n)
					continue;
				tx = rte_eth_tx_burst(pr->outer_port, 0,
					      pkts, n);
				pr->inst[s].c_out0 += tx;
				for (k = tx; k < n; k++)
					rte_pktmbuf_free(pkts[k]);
			}
		}
		if (pr->inner_port >= 0) {
			unsigned s;
			for (s = 0; s < pr->n_inst; s++) {
				if (!pr->inst[s].out1)
					continue;
				struct rte_mbuf *pkts[P4_BURST_SZ];
				uint16_t n = rte_ring_dequeue_burst(
					pr->inst[s].out1, (void **)pkts,
					P4_BURST_SZ, NULL), k, tx;
				if (!n)
					continue;
				tx = rte_eth_tx_burst(pr->inner_port, 0,
						      pkts, n);
				pr->inst[s].c_out1 += tx;
				for (k = tx; k < n; k++)
					rte_pktmbuf_free(pkts[k]);
			}
		}
	}
	return NULL;
}

/* Self-injecting TAP-FREE bench mode (env R2DP_P4_BENCH=1, launch --dp p4).

 * The normal worker bridges ethdev legs to the pipeline rings; a tap-free
 * measurement of the P4 data plane must bypass ethdev entirely (the net_tap
 * user<->kernel skb crossing caps lab throughput around a quarter Mpps and
 * hides the real SWX+crypto cost that fwd_bench exposes for the DPDK
 * backend).  This worker, launched INSTEAD of p4_worker, feeds the pipeline
 * directly: it waits until the control plane has bound at least one OUT
 * PROTECT policy (so the SPD->ipsec_protect path is armed), allocates a burst
 * of plaintext IPv4/UDP frames targeting that policy, then loops
 * enqueue(in1) -> rte_swx_pipeline_run -> rte_swx_ipsec_run -> dequeue(out0),
 * counting what the data plane accepts and egresses and reporting pps and
 * cycles/pkt from TSC.  No ethdev, no tap, no memif. */
#define P4_BENCH_WAIT_HZ 120     /* wait up to 120s for a bound OUT PROTECT
				* (the control plane installs SA+SP after
				* the forwarder is up, so this must cover
				* bring-up + a real policy install) */
#define P4_BENCH_SECS    3      /* timed window per trial */
#define P4_BENCH_TRIALS  5
/* Frame size for the tap-free sweep.  Default 64B (matches the originally
 * measured point); override with $R2DP_P4_BENCH_SIZE to sweep packet length.
 * The plaintext IPv4/UDP template is sized accordingly (total-len + UDP len
 * fields kept consistent so ESP encrypts a well-formed inner packet). */
static unsigned
p4_bench_size(void)
{
	const char *s = getenv("R2DP_P4_BENCH_SIZE");
	long v = s ? strtol(s, NULL, 10) : 64;
	if (v < 46) v = 46;          /* 14 eth + 20 ip + 8 udp + 4 min */
	if (v > 1500) v = 1500;
	return (unsigned)v;
}
static void *p4_bench_worker(void *arg)
{
	struct p4_inst *it = arg;
	struct p4_priv *pr = it->priv;
	p4_pin(it->s);
	unsigned waited = 0;

	while (atomic_load_explicit(&it->running, __ATOMIC_RELAXED) &&
	       waited++ < P4_BENCH_WAIT_HZ * 2) {
		for (int i = 0; i < P4_SP_MAX; i++) {
			struct p4_pol *q = &pr->spd[i];
			if (q->in_use && q->sp.dir == R2DP_DIR_OUT &&
			    q->sp.action == R2DP_ACT_PROTECT &&
			    q->bound_sl_id != UINT32_MAX)
				goto armed;
		}
		rte_delay_ms(500);
	}
	P4_LOG("bench: no bound OUT PROTECT within %ds; aborting",
	       P4_BENCH_WAIT_HZ);
	return NULL;
armed:
	/* Build one plaintext IPv4/UDP frame for src=10.0.0.1 dst=10.0.0.2
	 * proto=UDP dport=9 (the standard /32,/32 PROTECT selector).  We reuse
	 * a single template mbuf and clone per inject so substitution is
	 * exact.  mbuf pool must exist (tap mode has one; control-only does
	 * not, so create a local one here). */
	{
		struct rte_mempool *pool = NULL;
		unsigned fsz = p4_bench_size();   /* inner frame length */
		unsigned totlen, udplen;
		uint64_t t0, t1, min_c, best = 0, tot_pkt = 0;
		int trial;

		/* Isolated, per-slice bench pool: the whole point of the multicore
		 * sweep is that every slice is an independent single-owner data path,
		 * so each bench worker owns its own mbuf pool with a unique name (a
		 * shared pool under N workers is both a contention point and an
		 * EEXIST/ENOMEM hazard -- rte_pktmbuf_pool_create fails if the name
		 * already exists, so a second worker reusing 'p4bench_pool' would
		 * get NULL). */
		{
			char pn[64];
			snprintf(pn, sizeof(pn), "p4bench_pool%u", it->s);
			pool = rte_pktmbuf_pool_create(pn, P4_POOL_SIZE,
						       P4_POOL_CACHE, 128,
						       RTE_MBUF_DEFAULT_BUF_SIZE,
						       SOCKET_ID_ANY);
		}
		(void)pr->pool;
		if (!pool) {
			P4_LOG("bench: pool create failed");
			return NULL;
		}
		/* IPv4 total len = 20 (hdr) + 8 (udp) + payload; UDP len = 8 +
		 * payload.  fsz = 14 eth + ip; payload = fsz - 14 - 20 - 8. */
		totlen = fsz - 14;             /* ip hdr + udp + payload */
		udplen = fsz - 14 - 20;        /* udp hdr + payload */
		/* Time trials. */
		for (trial = 0; trial < P4_BENCH_TRIALS; trial++) {
			uint64_t end;
			uint64_t npkt = 0;
			/* drain any residue from the previous trial */
			{
				void *pkts[P4_BURST_SZ];
				uint16_t r;
				while ((r = rte_ring_dequeue_burst(it->out0,
								      pkts,
								      P4_BURST_SZ,
								      NULL))) {
					for (int k = 0; k < r; k++)
						rte_pktmbuf_free(pkts[k]);
				}
			}
			t0 = rte_get_tsc_cycles();
			end = t0 + (uint64_t)rte_get_tsc_hz() * P4_BENCH_SECS;
			while (rte_get_tsc_cycles() < end) {
				struct rte_mbuf *mk[P4_BURST_SZ];
				uint16_t n = 0, enq;
				/* alloc + build a burst of plaintext */
				for (int k = 0; k < P4_BURST_SZ; k++) {
					struct rte_mbuf *m =
					    rte_pktmbuf_alloc(pool);
					uint8_t *f;
					if (!m)
						break;
					f = (uint8_t *)rte_pktmbuf_append(m, fsz);
					if (!f) {
						rte_pktmbuf_free(m);
						break;
					}
					memset(f, 0, fsz);
					/* eth dst6 src6 + 0x0800 */
					f[0]=0x02; f[5]=0x01;
					f[6]=0x02; f[11]=0x02;
					f[12]=0x08; f[13]=0x00;
					/* IPv4 hdr @14: ver/ihl, tos,
					 * total len (be u16 @16, i.e.
					 * IP hdr offset 2-3), id, ttl
					 * 64, proto 17 udp */
					f[14]=0x45; f[15]=0x00;
					f[16]=(uint8_t)(totlen>>8);
					f[17]=(uint8_t)totlen;
					f[18]=0x00; f[19]=0x00;
					f[22]=0x40; f[23]=0x11;
					/* src 10.0.0.1 @26, dst 10.0.0.2 @30 */
					f[26]=0x0a; f[27]=0x00; f[28]=0x00;
					f[29]=0x01;
					f[30]=0x0a; f[31]=0x00; f[32]=0x00;
					f[33]=0x02;
					/* UDP @34: sport 1024, dport 9, len be */
					f[34]=0x04; f[35]=0x00;
					f[36]=0x00; f[37]=0x09;
					f[38]=(uint8_t)(udplen>>8);
					f[39]=(uint8_t)udplen;
					mk[n++] = m;
				}
				if (!n)
					break;
				/* feed the pipeline's inner leg */
				enq = rte_ring_enqueue_burst(it->in1,
							     (void **)mk,
							     n, NULL);
				/* free any not enqueued (ring full) */
				for (int k = enq; k < n; k++)
					rte_pktmbuf_free(mk[k]);
				/* run data plane */
				rte_swx_pipeline_run(it->p, P4_RUN_QUANTA);
				rte_swx_ipsec_run(it->ipsec);
				/* drain egress (ESP to the outer leg) */
				{
					struct rte_mbuf *rx[P4_BURST_SZ];
					uint16_t r =
					    rte_ring_dequeue_burst(it->out0,
								   (void **)rx,
								   P4_BURST_SZ,
								   NULL);
					npkt += r;
					for (int k = 0; k < r; k++)
						rte_pktmbuf_free(rx[k]);
				}
			}
			t1 = rte_get_tsc_cycles();
			npkt = npkt > 0 ? npkt : 1;
			min_c = (t1 - t0) / npkt;
			tot_pkt = npkt;
			best = (trial == 0 || min_c < best) ? min_c : best;
			P4_LOG("bench[%d] slice %u: pkt=%llu cyc/pkt=%llu pps=%llu",
			       trial, it->s,
			       (unsigned long long)npkt,
			       (unsigned long long)min_c,
			       (unsigned long long)((uint64_t)rte_get_tsc_hz() *
						    npkt / (t1 - t0)));
			(void)tot_pkt;
		}
		P4_LOG("bench[slice %u]: best_cyc_pkt=%llu", it->s,
		       (unsigned long long)best);
	}
	return NULL;
}

/* p4 stats dump (SIGUSR1 -> fwd_stats_req), mirroring the DPDK backend's
 * `stats ... spd_fail` / `drops ... tx_full` two-line format so the shared
 * bench harness (e2e_bench.sh ctr()) parses the P4 leg too.  Each 64-bit
 * counter load is atomic on the targets we build for.  out_rx/in_rx are the
 * eth RX totals, out0/out1 the eth TX totals; drop is billed from the eth RX
 * totals because only frames that reach an output ring are TXed (the pipeline
 * consumes the rest as spd_discard/drop or packets still in flight). */
static void
p4_stats_dump(struct p4_priv *p, FILE *f)
{
	unsigned long nrx = 0, ntx = 0, ndrop;
	unsigned sa_n = 0, sp_n = 0, i, s;

	/* Aggregate packet counters across all slices (a multicore forwarder
	 * reports the whole, not slice 0).  SAD/SPD mirror is shared, so count
	 * it once. */
	for (s = 0; s < p->n_inst; s++) {
		nrx += p->inst[s].c_outer + p->inst[s].c_inner;
		ntx += p->inst[s].c_out0 + p->inst[s].c_out1;
	}
	ndrop = (nrx > ntx) ? (nrx - ntx) : 0;
	for (i = 0; i < P4_SA_MAX; i++)
		sa_n += !!p->sad[i].in_use;
	for (i = 0; i < P4_SP_MAX; i++)
		sp_n += !!p->spd[i].in_use;
	fprintf(f, "r2dp-fwd: stats rx=%lu tx=%lu esp=%lu ike=%lu drop=%lu "
	    "spd_fail=%lu\n", nrx, ntx, 0ul, 0ul, ndrop, 0ul);
	fprintf(f, "r2dp-fwd: drops rx_bridge=%lu tx_full=%lu "
	    "(crypto_stuck_events=%lu outstanding=%u)\n",
	    ndrop, 0ul, 0ul, 0u);
	fprintf(f, "r2dp-fwd: tables sa=%u/%u sp=%u/%u sad=%u/%u sess_pools=%u "
	    "grows=0 grow_fail=0 acl_builds=0 acl_reuse=0\n",
	    sa_n, P4_SA_MAX, sp_n, P4_SP_MAX, sa_n, P4_SA_MAX, 0u);
}

/* Wait for the next SIGUSR1 dump: emit the `stats`/`drops`/`tables` lines the
 * e2e harness's ctr() parses, then drain a new-line count so a second USR1 is
 * not satisfied by the same printout.  No lock: like DPDK this is a snapshot. */
static void
p4_stats_on_req(struct p4_priv *p)
{
	p4_stats_dump(p, stderr);
	fwd_stats_req = 0;
}

static int p4_io_init(struct p4_priv *pr)
{
	static const char *const drv[] = { "tap", "memif", "vhost" };
	uint16_t port;

	pr->outer_port = pr->inner_port = -1;
	RTE_ETH_FOREACH_DEV(port) {
		struct rte_eth_dev_info di;
		int ok = 0;
		if (rte_eth_dev_info_get(port, &di) != 0)
			continue;
		for (size_t i = 0; i < RTE_DIM(drv); i++)
			ok |= strstr(di.driver_name, drv[i]) != NULL;
		if (!ok)
			continue;
		if (pr->outer_port < 0)
			pr->outer_port = port;
		else if (pr->inner_port < 0)
			pr->inner_port = port;
	}
	if (pr->outer_port < 0) {
		/* No NIC: run control-only (pipeline loads, no packet I/O). */
		P4_LOG("no tap/memif/vhost device; serving control-only");
		pr->outer_port = pr->inner_port = -1;
		return 0;
	}

	/* Cache the inner tap's own MAC so the inner next-hop entry can carry a
	 * unicast dst the inner host's kernel accepts. */
	memset(pr->our_inner_mac, 0, RTE_ETHER_ADDR_LEN);
	if (pr->inner_port >= 0) {
		struct rte_ether_addr mac;
		if (rte_eth_macaddr_get(pr->inner_port, &mac) == 0)
			memcpy(pr->our_inner_mac, mac.addr_bytes, RTE_ETHER_ADDR_LEN);
		P4_LOG("inner port=%d mac=%02x:%02x:%02x:%02x:%02x:%02x",
		       pr->inner_port, pr->our_inner_mac[0], pr->our_inner_mac[1],
		       pr->our_inner_mac[2], pr->our_inner_mac[3],
		       pr->our_inner_mac[4], pr->our_inner_mac[5]);
	}

	/* Tap-free bench mode (R2DP_P4_BENCH): the bench workers self-inject
	 * into their OWN per-slice pools and drain their own rings; they do not
	 * bridge eth legs.  Skip building one shared mbuf pool -- under N slices
	 * an extra static-allocation r2dp_p4_pool (8192 mbufs) plus N extern
	 * session pools exhausts --no-huge static EAL memory (W=4 'Invalid
	 * memory').  Each bench worker allocates its isolated pool lazily. */
	if (getenv("R2DP_P4_BENCH")) {
		P4_LOG("bench mode: skip eth/pool init");
		pr->pool = NULL;
		return 0;
	}

	pr->pool = rte_pktmbuf_pool_create("r2dp_p4_pool", P4_POOL_SIZE,
					   P4_POOL_CACHE,
					   /* priv >= sizeof(struct ipsec_mbuf):
					    * the SWX ipsec extern does
					    * rte_mbuf_to_priv() on every frame it
					    * consumes; with 0 bytes the crypto
					    * prepare fails and every packet is
					    * freed untouched.  Reference
					    * pipeline uses meta 128. */
					   128,
					   RTE_MBUF_DEFAULT_BUF_SIZE,
					   SOCKET_ID_ANY);
	if (!pr->pool) {
		P4_LOG("mbuf pool create failed");
		return -ENOMEM;
	}

	/* Configure one RX+TX queue and start each present leg. */
	{
		struct rte_eth_conf conf = {0};
		if (rte_eth_dev_configure((uint16_t)pr->outer_port, 1, 1,
					  &conf) < 0)
			return -EIO;
		if (rte_eth_rx_queue_setup((uint16_t)pr->outer_port, 0, 1024,
		    rte_eth_dev_socket_id((uint16_t)pr->outer_port), NULL,
		    pr->pool) < 0)
			return -EIO;
		if (rte_eth_tx_queue_setup((uint16_t)pr->outer_port, 0, 1024,
		    rte_eth_dev_socket_id((uint16_t)pr->outer_port), NULL) < 0)
			return -EIO;
		if (rte_eth_dev_start((uint16_t)pr->outer_port) < 0)
			return -EIO;
		rte_eth_promiscuous_enable((uint16_t)pr->outer_port);
		if (pr->inner_port >= 0) {
			if (rte_eth_dev_configure((uint16_t)pr->inner_port,
						  1, 1, &conf) < 0)
				return -EIO;
			if (rte_eth_rx_queue_setup((uint16_t)pr->inner_port,
			    0, 1024,
			    rte_eth_dev_socket_id((uint16_t)pr->inner_port),
			    NULL, pr->pool) < 0)
				return -EIO;
			if (rte_eth_tx_queue_setup((uint16_t)pr->inner_port,
			    0, 1024,
			    rte_eth_dev_socket_id((uint16_t)pr->inner_port),
			    NULL) < 0)
				return -EIO;
			if (rte_eth_dev_start((uint16_t)pr->inner_port) < 0)
				return -EIO;
			rte_eth_promiscuous_enable((uint16_t)pr->inner_port);
		}
	}
	P4_LOG("I/O: outer=port %d, inner=port %d", pr->outer_port,
	       pr->inner_port);
	return 0;
}

struct p4_priv;

/* Forward decls (defined below in the SPD mirror section). */
static int p4_spd_rebind(struct p4_priv *pr);

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

/* Write a NETWORK byte-order prefix mask for the top N bits of a 32-bit
 * field into out[4] (big-endian, byte0 = MSB): pref=32 -> ff ff ff ff,
 * pref=24 -> ff ff ff 00, pref=8 -> ff 00 00 00, pref=0 (ANY) -> 00 00 00 00.
 * The outbound SPD is a WILDCARD (ternary, SWX ACL) table; the ACL reads
 * header fields big-endian (acl_table_rule_field32, byte0=MSB), so the mask
 * must be the raw network-order prefix — same convention as the proven
 * routing 10/8 entry ({0xff,0,0,0}).  Emit MSB-first directly from the host
 * int (no htonl: that would byte-swap the MSB-first bytes below). */
static void pref2mask_bytes(uint8_t pref, uint8_t *out)
{
	uint32_t v = 0;
	int i;

	if (pref >= 32)
		v = 0xffffffffu;
	else if (pref > 0)
		v = 0xffffffffu << (32 - pref);
	for (i = 0; i < 4; i++)
		out[i] = (v >> (24 - 8 * i)) & 0xff;
}

/* Find the egress (encrypt) SA for an OUT PROTECT policy, binding by tunnel
 * endpoint like the DPDK backend's sa_by_policy (dpdk_spd.c): the policy's
 * tun_src/tun_dst must equal an outbound SA's src/dst; among overlaps take the
 * NEWEST INSTALL (highest gen), never the last slot index. */
static struct p4_sa *p4_spd_sa_lookup(struct p4_priv *pr,
				      const struct r2dp_sp *sp)
{
	struct p4_sa *best = NULL;
	uint32_t ts, td;
	int i;

	if (sp->tun_src.family != R2DP_AF_INET4 ||
	    sp->tun_dst.family != R2DP_AF_INET4)
		return NULL;
	memcpy(&ts, sp->tun_src.addr, 4);
	memcpy(&td, sp->tun_dst.addr, 4);
	ts = ntohl(ts); td = ntohl(td);

	for (i = 0; i < P4_SA_MAX; i++) {
		struct p4_sa *x = &pr->sad[i];
		if (!x->in_use || x->dir == R2DP_DIR_IN)
			continue;
		if (x->sip != ts || x->dip != td)
			continue;
		if (!best || x->gen > best->gen)
			best = x;
	}
	return best;
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

/* Resolve a pipeline table ID from its NAME.  p4c-dpdk emits the compiled
 * tables in its own order (which is NOT source order and can change when a
 * table is added or the program is reordered), so the control plane must not
 * assume any fixed table ID.  Enumerate via rte_swx_ctl_pipeline_info_get /
 * rte_swx_ctl_table_info_get and match by name.  Returns >=0 (id) or -ENOENT.
 * Called once per slice at bring-up; every table op then uses the resolved id
 * so an added/shifted table cannot silently re-target a different table. */
static int p4_table_id_by_name(struct rte_swx_pipeline *p, const char *name)
{
	struct rte_swx_ctl_pipeline_info pi;
	struct rte_swx_ctl_table_info ti;
	uint32_t i;
	int rc;

	memset(&pi, 0, sizeof(pi));
	rc = rte_swx_ctl_pipeline_info_get(p, &pi);
	if (rc)
		return -EIO;
	for (i = 0; i < pi.n_tables; i++) {
		memset(&ti, 0, sizeof(ti));
		rc = rte_swx_ctl_table_info_get(p, i, &ti);
		if (rc)
			continue;
		if (strcmp(ti.name, name) == 0)
			return (int)i;
	}
	return -ENOENT;
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
	cconf.nb_queue_pairs = (uint16_t)pr->n_inst;
	memset(&qconf, 0, sizeof(qconf));
	qconf.nb_descriptors = 2048;
	if (rte_cryptodev_configure(id, &cconf) < 0) {
		P4_LOG("cryptodev configure failed (%u qp)", pr->n_inst);
		return -EIO;
	}
	{
		/* one queue pair per slice */
		unsigned s;
		for (s = 0; s < pr->n_inst; s++)
			if (rte_cryptodev_queue_pair_setup(id, s, &qconf,
							   SOCKET_ID_ANY) < 0) {
				P4_LOG("cryptodev qp%u setup failed", s);
				return -EIO;
			}
	}
	if (rte_cryptodev_start(id) < 0) {
		P4_LOG("cryptodev start failed");
		return -EIO;
	}
	P4_LOG("crypto %s ready (%u qp)", rte_cryptodev_name_get(id),
	       pr->n_inst);
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
	{
		const char *ring_names[] = { "R2DP_IN0", "R2DP_IN1", "R2DP_OUT0",
					     "R2DP_OUT1", "IP_IN", "IP_OUT", NULL };
		int i;
		unsigned s;
		for (s = 0; s < pr->n_inst; s++) {
			for (i = 0; ring_names[i]; i++) {
				char nm[80];
				int rr;
				if (s == 0)
					snprintf(nm, sizeof(nm), "%s",
						 ring_names[i]);
				else
					snprintf(nm, sizeof(nm), "%s_%u",
						 ring_names[i], s);
				rr = p4_ring(nm);
				if (rr) { P4_LOG("ring %s: %s", nm,
						strerror(-rr)); return rr; }
			}
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
			/* Always regenerate the DEFAULT iospec: it must include the
			 * ipsec extern rings (port in 2 = IP_OUT, port out 2 =
			 * IP_IN) or the pipeline's tx-to-port-2 is a no-op and
			 * no framed ESP can ever reach the extern.  A stale .io
			 * left over from an earlier build (4 ports only) would
			 * otherwise be reused forever and silently break the
			 * ipsec path. */
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
				/* ipsec extern wiring (matches the DPDK
				 * ipsec example: the extern's return ring
				 * is a pipeline INPUT port and its consume
				 * ring is a pipeline OUTPUT port). */
				fputs("port in 2 ring IP_OUT bsz 32\n",
				      io_f);
				fputs("port out 2 ring IP_IN bsz 32\n",
				      io_f);
				fclose(io_f);
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

	/*
	 * Build one pipeline per slice.  The codegen C is compiled ONCE to a
	 * shared .so (all slices run the identical PNA program) and that .so is
	 * instantiated once per slice.  Slice 0 keeps the historical unsigned
	 * ring names (R2DP_IN0, IP_IN, ...) so N=1 is byte-identical; slices
	 * >=1 get a numeric suffix (R2DP_IN0_1, IP_IN_1, ...) so no two
	 * pipelines share a ring (rte_swx_* is single-owner; a shared ring
	 * across two workers is a data race).  The per-slice iospec is written
	 * to the scratch dir before each build_from_lib.
	 */
	{
		unsigned s;
		for (s = 0; s < pr->n_inst; s++) {
			char io_path[PATH_MAX + 32];
			char rn[80];
			FILE *io_f, *ir;
			snprintf(io_path, sizeof(io_path), "%s/%s_%u.io",
				 tmp, base, s);
			io_f = fopen(io_path, "w");
			if (!io_f) {
				P4_LOG("iospec %s: %s", io_path,
				       strerror(errno));
				return -errno;
			}
#define P4_IO_RING(pref, n) do { \
	if (s == 0) snprintf(rn, sizeof(rn), "%s", pref); \
	else        snprintf(rn, sizeof(rn), "%s_%u", pref, s); \
	fprintf(io_f, "port in  %d ring %s bsz 32\n", n, rn); \
	if (s) (void)0; \
} while (0)
#define P4_IO_RING_OUT(pref, o) do { \
	if (s == 0) snprintf(rn, sizeof(rn), "%s", pref); \
	else        snprintf(rn, sizeof(rn), "%s_%u", pref, s); \
	fprintf(io_f, "port out %d ring %s bsz 32\n", o, rn); \
} while (0)
			P4_IO_RING("R2DP_IN0", 0);
			P4_IO_RING("R2DP_IN1", 1);
			P4_IO_RING_OUT("R2DP_OUT0", 0);
			P4_IO_RING_OUT("R2DP_OUT1", 1);
			P4_IO_RING("IP_OUT", 2);
			P4_IO_RING_OUT("IP_IN", 2);
#undef P4_IO_RING
#undef P4_IO_RING_OUT
			fclose(io_f);
			ir = fopen(io_path, "r");
			if (!ir) {
				P4_LOG("iospec %s: %s", io_path,
				       strerror(errno));
				return -errno;
			}
			char pname[64];
			/* Unique pipeline name per slice: build_from_lib registers
			 * the name in the global RTE_SWX_PIPELINE EAL tailq and
			 * pipeline_register returns -EEXIST on a duplicate, so
			 * two slices must never share a name. */
			snprintf(pname, sizeof(pname), s ? "r2dp%u" : "r2dp", s);
			rc = rte_swx_pipeline_build_from_lib(&pr->inst[s].p,
							   pname, code_so,
							   ir, 0);
			fclose(ir);
			if (rc) {
				P4_LOG("slice %u build_from_lib %d", s, rc);
				return -EIO;
			}
		}
	}
	return 0;
}

static int p4_start(struct fwd_dp *dp)
{
	struct p4_priv *pr = dp->priv;
	const char *spec = pr->spec_path ? pr->spec_path : R2DP_P4_SPEC;
	int rc;
	unsigned s;

	if (pr->started)
		return 0;

	rc = p4_build_from_spec(pr, spec);
	if (rc)
		return rc;

	/* Cache table key sizes (inbound SAD, outbound SPD).  Identical for
	 * every slice (they share one compiled program), so cache once from
	 * slice 0.  Resolve the IDs by name (not hard-coded) so the cache is
	 * correct regardless of p4c-dpdk's table emission order. */
	{
		int t0 = p4_table_id_by_name(pr->inst[0].p, "inbound_table_0");
		int t1 = p4_table_id_by_name(pr->inst[0].p, "outbound_table_0");
		if (t0 < 0 || t1 < 0) {
			P4_LOG("key-size table id resolve inbt=%d outbt=%d", t0, t1);
			return -EIO;
		}
		rc = p4_table_key_size(pr->inst[0].p, (uint32_t)t0,
				       &pr->inbound_key_size);
		if (rc) {
			P4_LOG("inbound table info %d", rc);
			return -EIO;
		}
		rc = p4_table_key_size(pr->inst[0].p, (uint32_t)t1,
				       &pr->outbound_key_size);
		if (rc) {
			P4_LOG("outbound table info %d", rc);
			return -EIO;
		}
	}

	P4_LOG("table keys: inbound=%u outbound=%u", pr->inbound_key_size,
	       pr->outbound_key_size);

	/* One configured cryptodev with one queue pair per slice (the extern
	 * for slice s binds crypto_dev_queue_pair_id = s). */
	rc = p4_crypto_init(pr);
	if (rc)
		return rc;

	/*
	 * Per-slice bring-up.  Every slice is a full, independent copy of the
	 * PNA program: own ctl, own ipsec extern (on its own crypto QP and its
	 * own IP_IN/IP_OUT rings), own classification/tables, own worker.  The
	 * control plane (p4_sa_add / p4_sp_add / p4_sp_del / p4_spd_bind /
	 * p4_spd_rebind) later programs EVERY slice identically, so packet
	 * state is symmetric across replicas.
	 */
	for (s = 0; s < pr->n_inst; s++) {
		char rin[96], rout[96];

		pr->inst[s].priv = pr;
		pr->inst[s].s = s;

		pr->inst[s].ctl = rte_swx_ctl_pipeline_create(pr->inst[s].p);
		if (!pr->inst[s].ctl) {
			P4_LOG("slice %u ctl pipeline create failed", s);
			return -EIO;
		}

		/* Resolve the table IDs by name so control-plane ops target the
		 * right tables regardless of p4c-dpdk's emission order.  A resolved
		 * table absent from this program version fails here (fail-fast)
		 * rather than silently programming a shifted sibling table. */
		{
			/* resolve into signed ints: the stored IDs are
			 * unsigned, so a negative "not found" can only be
			 * caught before it is assigned (COMMITS C3) */
			int ib = p4_table_id_by_name(pr->inst[s].p, "inbound_table_0");
			int ob = p4_table_id_by_name(pr->inst[s].p, "outbound_table_0");
			int rt = p4_table_id_by_name(pr->inst[s].p, "routing_table_0");
			int nh = p4_table_id_by_name(pr->inst[s].p, "next_hop_table_0");
			int is = p4_table_id_by_name(pr->inst[s].p, "inbound_spd_table_0");

			if (ib < 0 || ob < 0 || rt < 0 || nh < 0 || is < 0) {
				P4_LOG("slice %u table id resolve: inbt=%d outbt=%d "
				       "routing=%d nhop=%d inspd=%d",
				       s, ib, ob, rt, nh, is);
				return -EIO;
			}
			pr->inst[s].tid_inbt    = (uint32_t)ib;
			pr->inst[s].tid_outbt   = (uint32_t)ob;
			pr->inst[s].tid_routing = (uint32_t)rt;
			pr->inst[s].tid_nhop    = (uint32_t)nh;
			pr->inst[s].tid_inspd   = (uint32_t)is;
		}

		/* ipsec extern instance the spec's ipsec_enable/protect actions
		 * resolve into; SA ids written to ipsec_hdr.sa_id are looked up
		 * here.  It needs a configured cryptodev (param validation
		 * requires one) and binds the slice's own crypto queue pair and
		 * its own rings so two workers never share a structure.  The
		 * extern NAME must be per-slice: rte_swx_ipsec_create names its
		 * crypto session pool "<name>_mp", and a duplicate name makes
		 * rte_cryptodev_sym_session_pool_create fail with EEXIST. */
		{
			char iname[64];
			snprintf(iname, sizeof(iname),
				 s ? "r2dp-ipsec%u" : "r2dp-ipsec", s);
			if (s == 0) {
				snprintf(rin, sizeof(rin), "%s", "IP_IN");
				snprintf(rout, sizeof(rout), "%s", "IP_OUT");
			} else {
				snprintf(rin, sizeof(rin), "IP_IN_%u", s);
				snprintf(rout, sizeof(rout), "IP_OUT_%u", s);
			}
			rc = rte_swx_ipsec_create(&pr->inst[s].ipsec, iname,
				&(struct rte_swx_ipsec_params){
					.ring_in_name    = rin,
					.ring_out_name   = rout,
					.crypto_dev_name = rte_cryptodev_name_get(
					    pr->cdev_id),
					.crypto_dev_queue_pair_id = s,
					.n_sa_max        = P4_SA_MAX,
					/* burst sizes must be non-zero or the
					 * extern never drains its input ring
					 * (bsz all 0 -> read 0 frames).  Reference
					 * ipsec.cli uses 32 32 32 32. */
					.bsz = { 32, 32, 32, 32 },
				  }, 0);
		}

		if (rc) {
			P4_LOG("slice %u ipsec_create %d", s, rc);
			return -EIO;
		}

		/* Program the classification regarrays the spec's parser/apply
		 * read (they default to 0).  See the pre-loop comment block in
		 * the original single-instance text: direction per port,
		 * ipsec_port_* = the extern port (2). */
		(void)rte_swx_ctl_pipeline_regarray_write(pr->inst[s].p,
			"direction", 0, 0);
		(void)rte_swx_ctl_pipeline_regarray_write(pr->inst[s].p,
			"direction", 1, 1);
		(void)rte_swx_ctl_pipeline_regarray_write(pr->inst[s].p,
			"ipsec_port_in_inbound", 0, 2);
		(void)rte_swx_ctl_pipeline_regarray_write(pr->inst[s].p,
			"ipsec_port_in_outbound", 0, 2);
		(void)rte_swx_ctl_pipeline_regarray_write(pr->inst[s].p,
			"ipsec_port_out_inbound", 0, 2);
		(void)rte_swx_ctl_pipeline_regarray_write(pr->inst[s].p,
			"ipsec_port_out_outbound", 0, 2);

		/* next_hop id0 -> outer leg (port 0), id1 -> inner (port 1). */
		{
			struct rte_swx_table_entry en;
			int rid = p4_table_action_id(pr->inst[s].p, pr->inst[s].tid_nhop, 0);
			uint8_t k0[4] = { 0, 0, 0, 0 }, k1[4] = { 1, 0, 0, 0 };
			uint8_t ab[18];
			if (rid < 0) {
				P4_LOG("slice %u next_hop_set lookup failed", s);
				return -EIO;
			}
			memset(&en, 0, sizeof(en));
			memset(ab, 0, sizeof(ab));
			ab[12] = 0x08; ab[13] = 0x00;
			en.action_id = (uint64_t)rid;
			en.action_data = ab;
			en.key = k0;
			if (rte_swx_ctl_pipeline_table_entry_add(pr->inst[s].ctl,
				 "next_hop_table_0", &en))
				P4_LOG("slice %u next_hop id0 add failed", s);
			ab[14] = 0x01; ab[15] = 0x00;
			ab[16] = 0x00; ab[17] = 0x00;
			en.key = k1;
			if (rte_swx_ctl_pipeline_table_entry_add(pr->inst[s].ctl,
				 "next_hop_table_0", &en))
				P4_LOG("slice %u next_hop id1 add failed", s);
			(void)rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1);
			P4_LOG("slice %u next_hop (id0->outer, id1->inner)", s);
		}

		/* Clear-forward hops: id2 -> inner, id3 -> outer (preserve). */
		{
			struct rte_swx_table_entry en;
			int rid = p4_table_action_id(pr->inst[s].p, pr->inst[s].tid_nhop, 1);
			uint8_t k2[4] = { 2, 0, 0, 0 }, k3[4] = { 3, 0, 0, 0 };
			uint8_t ab[4];
			if (rid < 0) {
				P4_LOG("slice %u preserve lookup failed", s);
				return -EIO;
			}
			memset(&en, 0, sizeof(en));
			memset(ab, 0, sizeof(ab));
			en.action_id = (uint64_t)rid;
			en.action_data = ab;
			ab[0] = 0x01;
			en.key = k2;
			if (rte_swx_ctl_pipeline_table_entry_add(pr->inst[s].ctl,
				"next_hop_table_0", &en)) {
				P4_LOG("slice %u id2 preserve add failed", s);
				return -EIO;
			}
			ab[0] = 0x00;
			en.key = k3;
			if (rte_swx_ctl_pipeline_table_entry_add(pr->inst[s].ctl,
				"next_hop_table_0", &en)) {
				P4_LOG("slice %u id3 preserve add failed", s);
				return -EIO;
			}
			if (rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1)) {
				P4_LOG("slice %u preserve commit failed", s);
				return -EIO;
			}
		}

		/* Decrypt egress 10/8 -> next_hop 1 (inner). See single-instance
		 * comment: fail-closed, a missing entry is a plaintext leak on
		 * the outer wire for decrypted 10/8 frames. */
		{
			struct rte_swx_table_entry en;
			int rid = p4_table_action_id(pr->inst[s].p, pr->inst[s].tid_routing, 0);
			uint8_t rkey[4] = { 0x0a, 0, 0, 0 };
			uint8_t rmask[4] = { 0xff, 0, 0, 0 };
			uint8_t rdata[4] = { 1, 0, 0, 0 };
			if (rid < 0) {
				P4_LOG("slice %u next_hop_id_set lookup failed", s);
				return -EIO;
			}
			memset(&en, 0, sizeof(en));
			en.key = rkey;
			en.key_mask = rmask;
			en.action_id = (uint64_t)rid;
			en.action_data = rdata;
			if (rte_swx_ctl_pipeline_table_entry_add(pr->inst[s].ctl,
				 "routing_table_0", &en)) {
				P4_LOG("slice %u routing 10/8 add failed", s);
				return -EIO;
			}
			if (rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1)) {
				P4_LOG("slice %u routing 10/8 commit failed", s);
				return -EIO;
			}
		}

		/* Grab this slice's ring handles (created in p4_build_from_spec)
		 * so its worker can bridge eth <-> pipeline.  Slice 0 keeps the
		 * historical unsigned names, slices >=1 the suffixed ones — must
		 * match the iospec written in p4_build_from_spec. */
		if (s == 0) {
			pr->inst[s].in0  = rte_ring_lookup("R2DP_IN0");
			pr->inst[s].in1  = rte_ring_lookup("R2DP_IN1");
			pr->inst[s].out0 = rte_ring_lookup("R2DP_OUT0");
			pr->inst[s].out1 = rte_ring_lookup("R2DP_OUT1");
		} else {
			char nm[96];
			snprintf(nm, sizeof(nm), "R2DP_IN0_%u", s);
			pr->inst[s].in0  = rte_ring_lookup(nm);
			snprintf(nm, sizeof(nm), "R2DP_IN1_%u", s);
			pr->inst[s].in1  = rte_ring_lookup(nm);
			snprintf(nm, sizeof(nm), "R2DP_OUT0_%u", s);
			pr->inst[s].out0 = rte_ring_lookup(nm);
			snprintf(nm, sizeof(nm), "R2DP_OUT1_%u", s);
			pr->inst[s].out1 = rte_ring_lookup(nm);
		}

		/* Launch this slice's packet-path worker (or the self-injecting
		 * bench worker when R2DP_P4_BENCH is set).  In the live path the
		 * per-slice worker only runs pipeline+extern; the single I/O thread
		 * owns both ethdev RX and TX.  In bench mode workers self-inject, so
		 * the I/O thread is not started. */
		atomic_store_explicit(&pr->inst[s].running, 1, __ATOMIC_RELAXED);
		{
			void *(*wk)(void *) = getenv("R2DP_P4_BENCH")
					      ? p4_bench_worker : p4_worker;
			if (pthread_create(&pr->inst[s].th, NULL, wk,
					   &pr->inst[s]) != 0) {
				P4_LOG("slice %u worker create failed", s);
				atomic_store_explicit(&pr->inst[s].running, 0,
						      __ATOMIC_RELAXED);
				return -EIO;
			}
		}
		pr->inst[s].th_started = 1;
		}

	/* Find + configure the two ethdev legs (tap/memif/vhost) and the mbuf
	 * pool; shared across slices.  A box with no such NIC runs
	 * control-only.  Done after workers exist so the worker's packets
	 * already have legs to drain to. */
	rc = p4_io_init(pr);
	if (rc)
		return rc;

	
	/* Program the inner next-hop MAC that p4_io_init just learned.  The
	 * id1 (inner) entry from the slice loop carried dst/src MACs we could
	 * not know before the ethdev legs were discovered; rewrite it with the
	 * inner tap's own MAC so a decrypted frame is handed unicast to the
	 * inner host instead of to 00:00:00:00:00:00 (which a real kernel
	 * drops, and which blocks any inner ICMP reply).  Mirrors dp_dpdk.c
	 * our_inner_mac.  Update every slice. */
	if (pr->inner_port >= 0) {
		int mac_is_zero = 1;
		for (int i = 0; i < RTE_ETHER_ADDR_LEN; i++)
			mac_is_zero &= pr->our_inner_mac[i] == 0;
		for (int s = 0; s < pr->n_inst && !mac_is_zero; s++) {
			struct rte_swx_table_entry en;
			int rid = p4_table_action_id(pr->inst[s].p, pr->inst[s].tid_nhop, 0);
			uint8_t k1[4] = { 1, 0, 0, 0 };
			uint8_t ab[18];
			if (rid < 0)
				continue;
			memset(&en, 0, sizeof(en));
			memset(ab, 0, sizeof(ab));
			memcpy(&ab[0], pr->our_inner_mac, RTE_ETHER_ADDR_LEN); /* dst */
			memcpy(&ab[6], pr->our_inner_mac, RTE_ETHER_ADDR_LEN); /* src */
			ab[12] = 0x08; ab[13] = 0x00;
			ab[14] = 0x01;                 /* port_id=1 -> inner */
			en.action_id = (uint64_t)rid;
			en.action_data = ab;
			en.key = k1;
			if (rte_swx_ctl_pipeline_table_entry_add(pr->inst[s].ctl,
				 "next_hop_table_0", &en))
				P4_LOG("slice %u inner-hop MAC add failed", s);
			else
				(void)rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1);
		}
	}

	/* Live path: start the single RX distributor (bench mode skips this
	 * because its workers self-inject and p4_io_init returns without
	 * legs).  One RX thread reads both legs and hashes each frame to a
	 * slice by flow, giving per-SA replay affinity and keeping the
	 * ethdev RX queue a single consumer. */
	if (!getenv("R2DP_P4_BENCH") && pr->outer_port >= 0) {
		if (pthread_create(&pr->rx_th, NULL, p4_io_worker, pr) != 0) {
			P4_LOG("io worker create failed");
			return -EIO;
		}
		pr->rx_started = 1;
		P4_LOG("io worker started (%u slices, hash steer)", pr->n_inst);
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
	uint32_t orig_sl_id[R2DP_P4_MAX_INST]; /* pre-rekey ids per slice (restore
					 * on bind/table fail) */
	int rc, i, inbound, deleting, new_slot = 0;
	uint32_t dip, spi, sa_sip = 0;

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
	if (sa->src.family == R2DP_AF_INET4) {
		memcpy(&sa_sip, sa->src.addr, 4);
		sa_sip = ntohl(sa_sip);
	} else {
		sa_sip = 0;
	}

	e = p4_sad_lookup(pr, dip, spi, sa->proto);
	if (deleting) {
		int isin;
		if (!e)
			return -ENOENT;
		/* Direction of a delete is NOT carried by the vtable flags (ctl
		 * passes add=0 with no FWD_DP_SA_INBOUND on R2DP_SA_DEL); use
		 * the direction we stored at install to pick the SAD table. */
		isin = (e->dir == R2DP_DIR_IN);
		if (isin) {
			/* remove the (dip,spi) -> ipsec_enable SAD entry.
			 * The key MUST be byte-identical to the one add installed
			 * (host dip || host spi, as empirically proven by the live
			 * inbound probe) or table_entry_delete no-ops and orphans
			 * the row.  Same convention as outbound_table_0. */
			memset(&ent, 0, sizeof(ent));
			memset(key, 0, sizeof(key));
			memcpy(&key[0], &dip, 4);
			memcpy(&key[4], &spi, 4);
			ent.key = key;
			{
				unsigned s;
				for (s = 0; s < pr->n_inst; s++) {
					rc = rte_swx_ctl_pipeline_table_entry_delete(
						pr->inst[s].ctl, "inbound_table_0", &ent);
					if (rc) {
						/* keep the slot live: the dataplane still owns
						 * the (dip,spi)->SA binding (ctl drops its entry
						 * only on success, dp.h/ctl.c contract).
						 * Slices 0..s-1 already have the delete
						 * SCHEDULED; abort() them or a later successful
						 * commit publishes the SAD drop while ctl still
						 * owns the SA (inbound miss = drop = blackhole). */
						for (unsigned t = 0; t < s; t++)
							rte_swx_ctl_pipeline_abort(
								pr->inst[t].ctl);
						P4_LOG("slice %u inbound entry del %d", s, rc);
						return rc;
					}
				}
			}
		}
		if (e->dir == R2DP_DIR_OUT) {
			/* Retarget/release outbound policies FIRST, while the SA being
			 * deleted is still in the crypto extern.  Mark the slot not-in-use
			 * so the lookup skips it, but do NOT free the crypto SA or slot
			 * until the rebind has succeeded: on failure we restore the slot
			 * and return, so ctl's keep-on-error contract holds and a retry
			 * can still find it. */
			e->in_use = 0;
			rc = p4_spd_rebind(pr);
			if (rc) {
				e->in_use = 1;   /* keep the live SA for ctl's retry */
				return rc;
			}
			/* Commit EVERY slice's scheduled rebind FIRST.  Only after all
			 * succeed do we delete the crypto SAs / clear the slot: a
			 * failed commit must leave the slot findable (in_use=1) and
			 * the crypto SA still present so ctl's retry is not -ENOENT
			 * with the SA gone.  With abort_on_fail=1 a failed commit
			 * rolls that slice's rebind back, keeping the old policy. */
			{
				unsigned s;
				for (s = 0; s < pr->n_inst; s++) {
					rc = rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1);
					if (rc) {
						/*
						 * Some slices committed the rebind,
						 * others did not.  Restore the slot
						 * so ctl's retry can find it; the
						 * committed slices' crypto SA is
						 * untouched (we have not deleted it
						 * yet), so retry is safe.
						 */
						e->in_use = 1;
						P4_LOG("slice %u out sa-del commit %d; "
						       "keeping SA", s, rc);
						return rc;
					}
				}
			}
			/* All commits succeeded: now safe to tear down the crypto
			 * SA on every slice and release the slot. */
			{
				unsigned s;
				for (s = 0; s < pr->n_inst; s++) {
					if (pr->inst[s].ipsec)
						rte_swx_ipsec_sa_delete(pr->inst[s].ipsec,
								 e->sl_id[s]);
					e->sl_id[s] = 0;
				}
			}
			e->in_use = 0;   /* already 0; keep for clarity */
			return 0;
		}
		/* Inbound delete: the (dip,spi) table delete is already scheduled.
		 * Apply it BEFORE tearing down the crypto SA / slot: with
		 * abort_on_fail=1 a failed commit rolls that slice's delete back,
		 * and ctl keeps the SA on error, so the dataplane must still own
		 * it. */
		{
			unsigned s;
			for (s = 0; s < pr->n_inst; s++) {
				rc = rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1);
				if (rc) {
					P4_LOG("slice %u inbound sa del commit %d; keeping SA",
					       s, rc);
					/* Slices s+1..n-1 still have the delete
					 * SCHEDULED.  abort() them or a later
					 * successful commit anywhere publishes the
					 * drop while ctl still owns the SA (inbound
					 * miss = drop = blackhole, but ctl's retry
					 * would then find the row gone).  Slices
					 * 0..s-1 already committed cannot be rolled
					 * back; ctl keeps the SA, so those slices
					 * keep the (now orphaned) SAD row until a
					 * retry commits. */
					for (unsigned t = s + 1; t < pr->n_inst; t++)
						rte_swx_ctl_pipeline_abort(
							pr->inst[t].ctl);
					return rc;
				}
			}
			for (s = 0; s < pr->n_inst; s++) {
				if (pr->inst[s].ipsec)
					rte_swx_ipsec_sa_delete(pr->inst[s].ipsec,
							 e->sl_id[s]);
				e->sl_id[s] = 0;
			}
			e->in_use = 0;
			return 0;
		}
	}

	if (!e) {
		for (i = 0; i < P4_SA_MAX; i++)
			if (!pr->sad[i].in_use) { e = &pr->sad[i]; break; }
		if (!e)
			return -ENOSPC;
		e->dip = dip;
		e->sip = sa_sip;
		e->spi = spi;
		e->proto = sa->proto;
		e->dir = inbound ? R2DP_DIR_IN : R2DP_DIR_OUT;
		for (unsigned s = 0; s < pr->n_inst; s++)
			e->sl_id[s] = (uint32_t)i;  /* stable per-install slot id */
		e->gen = ++pr->gen;
		e->in_use = 1;
		new_slot = 1;
	} else if (blob && blen) {
		/* UPDATE (rekey) of a live SA: remember the pre-rekey crypto id so a
		 * later failure can restore it, and bump gen so SPD rebind takes the
		 * new SA. */
		for (unsigned s = 0; s < pr->n_inst; s++)
			orig_sl_id[s] = e->sl_id[s];
		e->gen = ++pr->gen;
	}

	/* Crypto SA in the ipsec extern (spi -> cipher/AEAD params + key).
	 * r2dp provisions AES-GCM (see dp_gcm.c); `blob` is the AEAD key+salt
	 * (enckeylen bytes), and the extern strips the trailing 4 salt bytes. */
	if (blob && blen) {
		
		struct rte_swx_ipsec_sa_params sp = {0};
		sp.encrypt = !inbound;    /* encrypt = outbound */
		sp.crypto.is_aead = 1;
		sp.crypto.aead.alg = RTE_CRYPTO_AEAD_AES_GCM;
		if (blen > RTE_SWX_IPSEC_KEY_SIZE_MAX) {
			if (new_slot) {
				e->in_use = 0;
				e->sl_id[0] = 0;
			}
			return -E2BIG;
		}
		memcpy(sp.crypto.aead.key, blob, blen);
		sp.crypto.aead.key_size = (uint32_t)blen;   /* key || salt */
		/* The extern's ipsec_xform.spi must be HOST-order.  rte_swx_ipsec
		 * copies sp.encap.esp.spi straight into ipsec_xform.spi (no swap),
		 * and rte_ipsec stores it as sa->spi = rte_cpu_to_be_32(xform.spi)
		 * (lib/ipsec/sa.c) -- host order in, network order on the wire.
		 * This mirrors the DPDK backend (dp_gcm.c "spi = ntohl(rsa->spi)",
		 * dpdk_sad.c).  ctl hands sa->spi as network order (htonl at parse),
		 * so the raw value would be byte-swapped on the wire and in the GCM
		 * AAD (aead_gcm_aad_fill uses sa->spi): a mismatched AAD fails ICV in
		 * rte_ipsec_pkt_process after enqueue (enq and deq both move, inner
		 * egress stays 0).  ntohl makes the wire SPI + AAD correct.  NOTE:
		 * this is NOT the cause of the real-peer crypto enq=0 -- DPDK picks
		 * the SA by sa_id (meta), not by packet SPI, so a swapped SPI would
		 * still prepare and enqueue.  The real-peer ib=15 / crypto enq=0
		 * residual is a separate, unexplained defect. */
		sp.encap.esp.spi = ntohl(sa->spi);
		sp.encap.tunnel_mode = (sa->mode == R2DP_MODE_TUNNEL);
		sp.encap.tunnel_ipv4 = 1;
		/* Anti-replay window (RFC 4303 s3.4.3): carry the ctl SA's
		 * wsize/replay_win to the extern so rte_ipsec enforces a sliding
		 * window in esp_inb_pkt_process (a replay or too-old seq is
		 * dropped -> no reply).  0 disables anti-replay (PF_KEY
		 * sadb_sa_replay); the DPDK backend matches via replay_accept.
		 * rte_ipsec's window is INCLUSIVE at its top (esn_inb_check_sqn
		 * rejects only when sqn + win_sz < rsn->sqn, i.e. it holds
		 * win_sz+1 slots), whereas the r2dp/DPDK convention is strict
		 * (a 64-window holds dist 0..63, rejects dist >= 64).  Pass
		 * window-1 so rte_ipsec's inclusive top equals r2dp's strict
		 * window and both backends agree on the farthest-accepted slot. */
		sp.replay_win_sz = r2dp_sa_window(sa) ? r2dp_sa_window(sa) - 1 : 0;
		/* RFC 3948 ESP-in-UDP (NAT-T): carry the ctl SA's natt params to
		 * the extern.  udp_encap is set for BOTH directions so the
		 * extern/xform build the NAT-T headers.  How udp_encap is
		 * used per direction differs (mirroring rte_ipsec + dpdk_esp.c):
		 * - OUTBOUND: rte_ipsec inserts the UDP/4500 wrapper into
		 *   sa->hdr (esp_outb) and tunnel_ipv4_header_set sets the outer
		 *   proto to UDP.
		 * - INBOUND: the .p4 parser has already preserved the
		 *   ESP-in-UDP wrapper, and the extern's pre_crypto folds the
		 *   8-byte UDP header out itself before rte_ipsec (keyed on the
		 *   outer proto == UDP; the inbound xform is built udp_encap=0
		 *   via the extern sa_add copy, so esp_inb does not also strip).
		 * natt_sport/dport are network order from ctl; the extern takes
		 * host-order ports (rte_cpu_to_be_16 in sa.c). */
		if (sa->natt_type == R2DP_NATT_ESPINUDP) {
			sp.encap.udp_encap = 1;
			sp.encap.udp.sport = ntohs(sa->natt_sport);
			sp.encap.udp.dport = ntohs(sa->natt_dport);
			if (!sp.encap.udp.sport)
				sp.encap.udp.sport = 4500;
			if (!sp.encap.udp.dport)
				sp.encap.udp.dport = 4500;
		}
		if (sa->src.family == R2DP_AF_INET4)
			memcpy(&sp.encap.tunnel.ipv4.src_addr,
			       sa->src.addr, sizeof(struct in_addr));
		if (sa->dst.family == R2DP_AF_INET4)
			memcpy(&sp.encap.tunnel.ipv4.dst_addr,
			       sa->dst.addr, sizeof(struct in_addr));
		/* Add the crypto SA to EVERY slice's extern (all-or-nothing: on a
		 * partial failure the already-added slices are deleted so the mirror
		 * stays symmetric and a retry re-adds cleanly).  Each extern returns
		 * its own sa_id, stored in e->sl_id[s]; table entries and rollbacks
		 * use the per-slice id. */
		{
			unsigned s;
			for (s = 0; s < pr->n_inst; s++) {
				uint32_t sid = 0;
				rc = rte_swx_ipsec_sa_add(pr->inst[s].ipsec, &sp, &sid);
				if (rc) {
					P4_LOG("slice %u ipsec sa_add %d", s, rc);
					for (unsigned t = 0; t < s; t++)
						if (pr->inst[t].ipsec)
							rte_swx_ipsec_sa_delete(
								pr->inst[t].ipsec,
								e->sl_id[t]);
					if (new_slot) {
						e->in_use = 0;
						for (unsigned u = 0; u < pr->n_inst; u++)
							e->sl_id[u] = 0;
					}
					return rc;
				}
				e->sl_id[s] = sid;
				P4_LOG("slice %u ipsec SA add ok id=%u spi=%08x mode=%d",
				       s, sid, sa->spi, sa->mode);
			}
		}
	}

	/* Only the inbound (decrypt) SA gets a SAD table entry; outbound SAs
	 * are reached through the SPD's ipsec_protect(sa_id).  Binding an
	 * outbound SA (re)targets any OUT PROTECT policy waiting on this
	 * tunnel (policy-installed-before-SA, or a rekey). */
	if (!inbound) {
		/* Binding an outbound SA (re)targets any OUT PROTECT policy
		 * waiting on this tunnel.  On failure, delete the just-added
		 * crypto SA and roll back the slot to its pre-call state so
		 * ctl's keep-on-error contract and a retry stay consistent. */
		rc = p4_spd_rebind(pr);
		if (rc) {
			{
				unsigned s;
				for (s = 0; s < pr->n_inst; s++)
					if (pr->inst[s].ipsec)
						rte_swx_ipsec_sa_delete(pr->inst[s].ipsec,
								 e->sl_id[s]);
			}
			if (new_slot) {
				e->in_use = 0;
				for (unsigned u = 0; u < pr->n_inst; u++)
					e->sl_id[u] = 0;
			} else {
				/* rekey: restore the pre-rekey crypto id (still
				 * live in the extern); the new one is deleted
				 * above. */
				for (unsigned u = 0; u < pr->n_inst; u++)
					e->sl_id[u] = orig_sl_id[u];
			}
			return rc;
		}
		{
			unsigned s;
			for (s = 0; s < pr->n_inst; s++) {
				rc = rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1);
				if (rc)
					return rc;
			}
		}
		return 0;
	}

	/* inbound_table_0 entry: (ipv4.dst_addr, esp.spi)
	 * -> ipsec_enable(sl_id).  EMPIRICALLY VERIFIED (live probe,
	 * 2026-11-08): SWX matches these parse fields as HOST-order uint32
	 * values, so the control-plane key must be `host dip || host spi`
	 * (both already computed above via ntohl).  A network-order / raw-wire
	 * key (memcpy of sa->dst.addr, sa->spi) MISSES every frame -- the
	 * original bug was an inconsistent mix: host dip + network spi.
	 * Action data (sa_id -> h.ipsec_hdr.sa_id) is stored network order. */
	memset(&ent, 0, sizeof(ent));
	/* The inbound (dip,spi) -> ipsec_enable(sa_id) entry is added to
	 * every slice.  The key (host dip, host spi) is identical across
	 * slices, but the action data carries that slice's own sa_id, so each
	 * slice is programmed with its per-slice id. */
	for (unsigned s = 0; s < pr->n_inst; s++) {
		uint32_t id_be = htonl(e->sl_id[s]);
		memset(key, 0, sizeof(key));
		/* match-field order from the spec: dst_addr then spi; host order
		 * (ntohl'd dip and host SPI), as empirically required by SWX. */
		memcpy(&key[0], &dip, 4);           /* host BE dst 0xC0000201 */
		memcpy(&key[4], &spi, 4);           /* host BE spi (ntohl'd)   */
		memcpy(data, &id_be, 4);
		ent.key = key;
		ent.action_id = (uint64_t)p4_table_action_id(pr->inst[s].p, pr->inst[s].tid_inbt, 0);
		ent.action_data = data;
		rc = rte_swx_ctl_pipeline_table_entry_add(pr->inst[s].ctl,
						  "inbound_table_0", &ent);
		if (rc) {
			/* Roll back the crypto SAs and the local slot: a
			 * second install would otherwise allocate fresh
			 * sa_ids and leak them.  Only do this for a freshly
			 * allocated slot -- an in-place rekey (new_slot==0)
			 * must keep its prior live SA, not have it deleted
			 * out from under it. */
			P4_LOG("slice %u inbound entry add %d", s, rc);
			for (unsigned u = 0; u <= s; u++)
				if (pr->inst[u].ipsec)
					rte_swx_ipsec_sa_delete(
						pr->inst[u].ipsec,
						e->sl_id[u]);
			if (new_slot) {
				e->in_use = 0;
				for (unsigned u = 0; u < pr->n_inst; u++)
					e->sl_id[u] = 0;
			} else {
				/* rekey: restore the pre-rekey id, which is
				 * still the live binding. */
				for (unsigned u = 0; u < pr->n_inst; u++)
					e->sl_id[u] = orig_sl_id[u];
			}
			return rc;
		}
		rc = rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1);
		if (rc) {
			P4_LOG("slice %u inbound entry commit %d", s, rc);
			return rc;
		}
	}
	return 0;
}

/* ---- SPD policy mirror ---- */

/* Match a policy against the mirror by selector -- the full ctl identity
 * (sel_eq_d): dir, ul_proto, pref_src, pref_dst, family, scope, ports, addr.
 * The P4 ACL row keys only (proto, masked src, masked dst); the extra fields
 * keep the mirror 1:1 with ctl so a delete finds exactly the policy it
 * installed.  Note scope is compared here ONLY (identity), never added to the
 * ACL key image -- it is not a match field, so two policies differing only by
 * scope are distinct in the mirror and collide on one row, which
 * p4_pol_row_conflicts rejects (-E2BIG). */
static struct p4_pol *p4_pol_find(struct p4_priv *pr, const struct r2dp_sp *sp)
{
	int i;
	for (i = 0; i < P4_SP_MAX; i++) {
		struct p4_pol *p = &pr->spd[i];
		const struct r2dp_sp *q = &p->sp;
		if (!p->in_use)
			continue;
		if (q->dir != sp->dir || q->ul_proto != sp->ul_proto)
			continue;
		if (q->pref_src != sp->pref_src || q->pref_dst != sp->pref_dst)
			continue;
		if (q->sel_src.family != sp->sel_src.family ||
		    q->sel_dst.family != sp->sel_dst.family)
			continue;
		if (q->sel_src.port != sp->sel_src.port ||
		    q->sel_dst.port != sp->sel_dst.port)
			continue;
		if (q->sel_src.scope != sp->sel_src.scope ||
		    q->sel_dst.scope != sp->sel_dst.scope)
			continue;
		if (memcmp(q->sel_src.addr, sp->sel_src.addr, 4) != 0)
			continue;
		if (memcmp(q->sel_dst.addr, sp->sel_dst.addr, 4) != 0)
			continue;
		return p;
	}
	return NULL;
}

/* Do two selectors map to the SAME ACL row in outbound_table_0?  The table is
 * a WILDCARD (ternary) keyed on (protocol, masked src, masked dst) only --
 * ports, scope, and host bits below the prefix are NOT part of the ACL key.
 * Two policies that differ ONLY in port, scope, or host bits inside the
 * prefix (/24 10.0.0.5 vs /24 10.0.0.0), are one row.  The control plane's
 * mirror (ctl sel_eq_d) keys on the full selector, so the ACL cannot name
 * both; p4_sp_add must reject the second rather than -EEXIST-replace and
 * report success (a later SP_DEL of either then deletes the row for BOTH --
 * fail-open).  Returns 1 if they collide on a row, 0 if both can coexist.
 * Scope/port/host-bits are compared ONLY here (identity/alias); they are
 * never written into the ACL key image (not match fields). */
static int
p4_pol_row_conflicts(const struct r2dp_sp *a, const struct r2dp_sp *b)
{
	uint8_t ma[8], mb[8];
	int i;

	if (a->dir != b->dir || a->ul_proto != b->ul_proto ||
	    a->pref_src != b->pref_src || a->pref_dst != b->pref_dst)
		return 0;
	if (a->sel_src.family != b->sel_src.family ||
	    a->sel_dst.family != b->sel_dst.family ||
	    a->sel_src.family != R2DP_AF_INET4)
		return 0;
	pref2mask_bytes(a->pref_src, &ma[0]);
	pref2mask_bytes(a->pref_dst, &ma[4]);
	pref2mask_bytes(b->pref_src, &mb[0]);
	pref2mask_bytes(b->pref_dst, &mb[4]);
	/* Mask each selector addr to its prefix; equal masked seeds => the
	 * two selectors differ only in port or host bits => one ACL row. */
	for (i = 0; i < 4; i++)
		if ((a->sel_src.addr[i] & ma[i]) != (b->sel_src.addr[i] & mb[i]))
			return 0;
	for (i = 0; i < 4; i++)
		if ((a->sel_dst.addr[i] & ma[4 + i]) !=
		    (b->sel_dst.addr[i] & mb[4 + i]))
			return 0;
	return 1;
}

/* SPD rule priority for the wildcard (ACL) outbound table.  rte_swx_table_wm.c
 * sets acl_rule->data.priority = RTE_ACL_MAX_PRIORITY - entry->key_priority,
 * and rte_acl returns the HIGHEST-priority matching rule.  So the rule that
 * should win (most specific: longest src+dst prefix, concrete proto) must have
 * the LOWEST key_priority.  p4_spd_prio returns 0 for /32,/32 concrete-proto
 * and grows as the selector broadens (ANY proto, /0), so a /32,/32 PROTECT
 * beats a /0,/0 ANY that also matches. */
static uint32_t p4_spd_prio(const struct r2dp_sp *sp)
{
	uint32_t v = 0;

	v += (32u - sp->pref_src) + (32u - sp->pref_dst);
	if (sp->ul_proto == R2DP_PROTO_ANY)
		v += 1;
	return v;
}

/* Write one OUT policy to outbound_table_0.  PROTECT binds to the newest
 * matching egress SA (highest gen).  If no egress SA exists YET we still
 * accept the policy (spmd installs SPD before IKE) but program it to
 * DISCARD -- never bypass: an OUT PROTECT with no SA must not forward in
 * the clear (dpdk_esp.c DR_NO_SA_OUT).  A later SA_ADD rebinds to
 * ipsec_protect.  Returns 0/errno. */

/* Build the SPD table key image for a policy, used by BOTH bind and del so a
 * deleted row is by construction the one bind installed (a mismatched image
 * makes table_entry_delete silently no-op and orphan the ACL row).
 * outbound_table_0 is a WILDCARD (ternary, SWX ACL) table keyed on the IPv4
 * header fields (protocol, src_addr, dst_addr).  The ACL key image is
 * GAP-AWARE, not packed: table_params_get builds key_mask0 from real header
 * bit-offsets, so relative to the first field (protocol @ IPv4 byte 9):
 * protocol@0, checksum-gap@1-2, src_addr@3-6, dst_addr@7-10, key_size=11.
 * A contiguous [proto][src][dst] image misses every lookup.  Key/mask bytes
 * are NETWORK order (big-endian; acl_table_rule_field32 reads header fields
 * that way), masks MSB-first. */
static void p4_spd_key_image(const struct r2dp_sp *sp, uint8_t *key,
			     uint8_t *mask)
{
	memset(key, 0, 16);
	memset(mask, 0, 16);
	key[0] = sp->ul_proto;
	memcpy(&key[3], sp->sel_src.addr, 4);
	memcpy(&key[7], sp->sel_dst.addr, 4);
	mask[0] = (sp->ul_proto == R2DP_PROTO_ANY) ? 0x00 : 0xff;
	pref2mask_bytes(sp->pref_src, &mask[3]);
	pref2mask_bytes(sp->pref_dst, &mask[7]);
}

static int p4_spd_bind(struct p4_priv *pr, struct p4_pol *p)
{
	struct r2dp_sp *sp = &p->sp;
	uint8_t key[16], mask[16], data[4];
	struct rte_swx_table_entry ent;
	uint32_t ssrc, sdst;
	struct p4_sa *ea;
	int rc;

	/* IPv4 selectors only; the ACL row keys (proto, masked src, masked dst)
	 * and nothing else -- ports/scope are not match fields (a policy that
	 * differs from a live one only by port/scope/host-bits collides on the
	 * row and is rejected by p4_sp_add/-E2BIG before reaching here). */
	if (sp->sel_src.family != R2DP_AF_INET4 ||
	    sp->sel_dst.family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;
	memcpy(&ssrc, sp->sel_src.addr, 4);
	memcpy(&sdst, sp->sel_dst.addr, 4);
	ssrc = ntohl(ssrc); sdst = ntohl(sdst);

	memset(&ent, 0, sizeof(ent));
	p4_spd_key_image(sp, key, mask);
	ent.key = key;
	ent.key_mask = mask;
	ent.key_priority = p4_spd_prio(sp);

	/* The bound egress SA (if any) arms the bench; keep a representative
	 * (slice-0) id in p->bound_sl_id -- every slice is programmed with the
	 * same logical policy, differentiated only by its own per-slice sa_id. */
	switch (sp->action) {
	case R2DP_ACT_DISCARD:
	case R2DP_ACT_PROTECT:
		ea = p4_spd_sa_lookup(pr, sp);
		p->bound_sl_id = ea ? ea->sl_id[0] : UINT32_MAX;
		if (ea)
			P4_LOG("OUT PROTECT bind sa_id=%u (slice 0)",
			       ea->sl_id[0]);
		else
			/* unbound OUT PROTECT: FAIL CLOSED (spd_discard),
			 * never bypass.  A later SA_ADD upgrades it to
			 * ipsec_protect. */
			P4_LOG("OUT PROTECT unbound -> DISCARD");
		break;
	default:                       /* BYPASS */
		p->bound_sl_id = UINT32_MAX;
		break;
	}

	/* Program the SAME selector row into EVERY slice's outbound table.
	 * The key/mask/priority are slice-independent; the PROTECT action
	 * data carries that slice's own sa_id, so each slice is bound with
	 * its per-slice id.  All-or-nothing: a partial failure returns the
	 * error (the caller aborts/doesn't commit); a divergent partial bind
	 * is better surfaced than silently half-programmed. */
	for (unsigned s = 0; s < pr->n_inst; s++) {
		switch (sp->action) {
		case R2DP_ACT_DISCARD:
			ent.action_id = (uint64_t)p4_table_action_id(
				pr->inst[s].p, pr->inst[s].tid_outbt, 2);
			break;
		case R2DP_ACT_PROTECT:
			ea = p4_spd_sa_lookup(pr, sp);
			if (ea) {
				uint32_t id_be = htonl(ea->sl_id[s]);
				memcpy(data, &id_be, 4);
				ent.action_id = (uint64_t)
					p4_table_action_id(pr->inst[s].p,
							pr->inst[s].tid_outbt, 0);
				ent.action_data = data;
			} else {
				ent.action_id = (uint64_t)
					p4_table_action_id(pr->inst[s].p,
							pr->inst[s].tid_outbt, 2);
			}
			break;
		default:                       /* BYPASS */
			ent.action_id = (uint64_t)p4_table_action_id(
				pr->inst[s].p, pr->inst[s].tid_outbt, 1);
			break;
		}

		/* Add.  On DPDK 24.11.4 table_entry_add does NOT return
		 * -EEXIST: a duplicate-key hit is moved to pending_modify and
		 * add returns 0 (rebind/bind-in-place).  The -EEXIST
		 * ->delete-then-add branch below is therefore dead against
		 * this DPDK -- keep it defensively for other backends/
		 * versions, but it is not the executing re-bind path.  Do NOT
		 * delete first unconditionally: a delete+failed-add would
		 * commit the deletion and leave the selector at the default. */
		rc = rte_swx_ctl_pipeline_table_entry_add(pr->inst[s].ctl,
					  "outbound_table_0", &ent);
		if (rc == -EEXIST) {
			(void)rte_swx_ctl_pipeline_table_entry_delete(
				pr->inst[s].ctl, "outbound_table_0", &ent);
			rc = rte_swx_ctl_pipeline_table_entry_add(
				pr->inst[s].ctl, "outbound_table_0", &ent);
			if (rc) {
				/* The delete above is already scheduled; a
				 * later commit would drop this selector to the
				 * (bypass) default.  Abort so the previous
				 * entry (e.g. the unbound DISCARD or a prior
				 * protect) is not silently removed. */
				rte_swx_ctl_pipeline_abort(pr->inst[s].ctl);
			}
		}
		if (rc) {
			/* Abort EVERY slice that scheduled an op so nothing is left
			 * pending: a pending delete/add on slices 0..s-1 would
			 * otherwise be committed by a later success, silently
			 * dropping this selector to the (bypass) default -- the
			 * delayed fail-open this tree fixes for N=1, now for all
			 * N.  abort on a slice with no pending op is a no-op. */
			for (unsigned u = 0; u < pr->n_inst; u++)
				if (pr->inst[u].ctl)
					rte_swx_ctl_pipeline_abort(pr->inst[u].ctl);
			P4_LOG("slice %u outbound entry add %d; aborted all", s, rc);
			return rc;
		}
		P4_LOG("slice %u OUT BIND installed sel=%08x/%08x proto=%u "
		       "action=%u",
		       s, ssrc, sdst, sp->ul_proto, (unsigned)ent.action_id);
	}
	return 0;
}

/* Write one IN policy to inbound_spd_table_0 (RFC 4301 fail-closed).
 * inbound_spd_table_0 is the same WILDCARD (ternary) ACL keyed on the same
 * (proto, masked src, masked dst) image as outbound_table_0, but it is
 * applied on the inbound CLEAR (non-ESP) path: a clear IPv4 frame whose
 * selector matches an inbound PROTECT/DISCARD policy is DROPPED
 * (ipsec_require) rather than forwarded into the protected inner net.
 * BYPASS policies (and the wildcard default) clear-forward, so IKE / ARP /
 * NAT-T keepalive / non-protected traffic is unaffected.
 *
 * Table ID is resolved by name at bring-up (p4_table_id_by_name) because
 * p4c-dpdk emits tables in its own (non-source) order -- a hard-coded index
 * would silently re-target a sibling after the program is reordered.  The
 * action indices come from the compiled spec: { ipsec_require;
 * spd_bypass_1; drop_4; } -> 0 = ipsec_require (drop), 1 = spd_bypass.
 * Same all-or-nothing multi-slice + abort discipline as p4_spd_bind. */
static int p4_inspd_bind(struct p4_priv *pr, struct p4_pol *p)
{
	struct r2dp_sp *sp = &p->sp;
	uint8_t key[16], mask[16];
	struct rte_swx_table_entry ent;
	uint32_t ssrc, sdst;
	uint32_t aidx;
	int rc;

	if (sp->sel_src.family != R2DP_AF_INET4 ||
	    sp->sel_dst.family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;
	memcpy(&ssrc, sp->sel_src.addr, 4);
	memcpy(&sdst, sp->sel_dst.addr, 4);
	ssrc = ntohl(ssrc); sdst = ntohl(sdst);

	/* Fail-closed mapping: PROTECT and DISCARD both drop the clear frame;
	 * only BYPASS keeps it flowing. */
	aidx = (sp->action == R2DP_ACT_BYPASS) ? 1u : 0u;

	memset(&ent, 0, sizeof(ent));
	p4_spd_key_image(sp, key, mask);
	ent.key = key;
	ent.key_mask = mask;
	ent.key_priority = p4_spd_prio(sp);

	for (unsigned s = 0; s < pr->n_inst; s++) {
		ent.action_id = (uint64_t)p4_table_action_id(
			pr->inst[s].p, pr->inst[s].tid_inspd, aidx);
		rc = rte_swx_ctl_pipeline_table_entry_add(pr->inst[s].ctl,
					       "inbound_spd_table_0", &ent);
		if (rc == -EEXIST) {
			(void)rte_swx_ctl_pipeline_table_entry_delete(
				pr->inst[s].ctl, "inbound_spd_table_0", &ent);
			rc = rte_swx_ctl_pipeline_table_entry_add(
				pr->inst[s].ctl, "inbound_spd_table_0", &ent);
			if (rc)
				rte_swx_ctl_pipeline_abort(pr->inst[s].ctl);
		}
		if (rc) {
			for (unsigned u = 0; u < pr->n_inst; u++)
				if (pr->inst[u].ctl)
					rte_swx_ctl_pipeline_abort(
						pr->inst[u].ctl);
			P4_LOG("slice %u inbound_spd entry add %d", s, rc);
			return rc;
		}
		P4_LOG("slice %u IN BIND sel=%08x/%08x proto=%u action=%u "
		       "aidx=%u",
		       s, ssrc, sdst, sp->ul_proto,
		       (unsigned)ent.action_id, aidx);
	}
	return 0;
}

static int p4_spd_rebind(struct p4_priv *pr)
{
	int i, rerr = 0;
	for (i = 0; i < P4_SP_MAX; i++) {
		struct p4_pol *p = &pr->spd[i];
		int rc;
		if (!p->in_use)
			continue;
		if (p->sp.action != R2DP_ACT_PROTECT ||
		    p->sp.dir != R2DP_DIR_OUT)
			continue;
		rc = p4_spd_bind(pr, p);
		if (rc && !rerr)
			rerr = rc;
	}
	if (rerr) {
		/* Abort ALL pending table ops (not just this bind) on EVERY slice:
		 * a scheduled delete whose paired add failed would otherwise be
		 * committed by a later success, dropping the selector to the
		 * (bypass) default -- the exact fail-open this path is meant to
		 * prevent. */
		for (unsigned s = 0; s < pr->n_inst; s++)
			rte_swx_ctl_pipeline_abort(pr->inst[s].ctl);
		return rerr;
	}
	for (unsigned s = 0; s < pr->n_inst; s++) {
		int crc = rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1);
		if (crc) {
			/* Slices s+1..n-1 still have the rebind SCHEDULED
			 * (p4_spd_bind does not commit).  A later successful
			 * commit anywhere would publish it and change the SPD
			 * after ctl's SA op already failed/rolled back.  Abort
			 * the uncommitted slices so the exclusion is not
			 * published late.  Slices 0..s-1 already committed cannot
			 * be undone. */
			for (unsigned t = s + 1; t < pr->n_inst; t++)
				rte_swx_ctl_pipeline_abort(pr->inst[t].ctl);
			return crc;
		}
	}
	return 0;
}

static int p4_sp_del(struct fwd_dp *dp, const struct r2dp_sp *sp)
{
	struct p4_priv *pr = dp->priv;
	struct p4_pol *p;
	uint8_t key[16], mask[16];
	struct rte_swx_table_entry ent;
	int rc;

	p = p4_pol_find(pr, sp);
	if (!p) {
		/* A non-OUT policy is never stored here (p4_sp_add returns 0
		 * for IN/FWD without keeping it), so deleting it is a no-op
		 * success -- NOT -ENOENT, which would make ctl keep its entry
		 * forever (it refuses to drop what the dataplane still owns). */
		if (sp->dir != R2DP_DIR_OUT)
			return 0;
		return -ENOENT;
	}
	if (sp->sel_src.family != R2DP_AF_INET4 ||
	    sp->sel_dst.family != R2DP_AF_INET4)
		return -EAFNOSUPPORT;

	memset(&ent, 0, sizeof(ent));
	/* Use the SAME key image builder as p4_spd_bind; a mismatched image
	 * (e.g. the pre-helper packed [1][5] layout) makes table_entry_delete
	 * silently no-op and orphan the ACL row. */
	p4_spd_key_image(&p->sp, key, mask);
	ent.key = key;
	ent.key_mask = mask;
	ent.key_priority = p4_spd_prio(&p->sp);
	{
		/* Delete from the table the policy's own direction was bound
		 * to: OUT -> outbound_table_0, IN -> inbound_spd_table_0. */
		const char *tname = (p->sp.dir == R2DP_DIR_OUT) ?
			"outbound_table_0" : "inbound_spd_table_0";
		unsigned s;
		/* Phase 1: schedule the delete on EVERY slice with no commit.
		 * All-or-nothing across slices: if scheduling fails on slice k,
		 * abort every slice that already scheduled (a pending delete on
		 * slices 0..k-1 would otherwise commit later and drop the
		 * selector to bypass -- the delayed fail-open).  No delete is
		 * published until every slice has accepted the schedule. */
		for (s = 0; s < pr->n_inst; s++) {
			rc = rte_swx_ctl_pipeline_table_entry_delete(pr->inst[s].ctl,
				     tname, &ent);
			if (rc) {
				for (unsigned u = 0; u < pr->n_inst; u++)
					if (pr->inst[u].ctl)
						rte_swx_ctl_pipeline_abort(pr->inst[u].ctl);
				P4_LOG("slice %u %s entry del %d; aborted all",
				       s, tname, rc);
				return rc;
			}
		}
		/* Phase 2: commit every slice's scheduled delete.  Do NOT clear
		 * the mirror before ALL succeed: with abort_on_fail=1 a failed
		 * commit rolls that slice's delete back and ctl keeps the policy
		 * on error, so the mirror must too (else the next rebind
		 * re-programs a policy ctl already dropped, and the bucket they
		 * agree on never empties).  A slice whose commit already
		 * succeeded cannot be rolled back here; that is the residual
		 * cross-slice hazard of per-pipeline commits (documented), but
		 * the common failure is symmetric, and an aborted schedule never
		 * leaks. */
		for (s = 0; s < pr->n_inst; s++) {
			rc = rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1);
			if (rc) {
				P4_LOG("slice %u sp_del commit %d; keeping policy", s, rc);
				return rc;
			}
		}
	}
	p->in_use = 0;
	memset(&p->sp, 0, sizeof(p->sp));
	p->bound_sl_id = UINT32_MAX;
	return 0;
}

static int p4_sp_add(struct fwd_dp *dp, struct r2dp_sp *sp)
{
	struct p4_priv *pr = dp->priv;
	struct p4_pol *p;
	struct r2dp_sp saved_sp;
	uint32_t saved_bound, saved_in_use;
	int was_live = 0;
	int rc, i;

	/* A control plane that does not ask for a slid assigns one before
	 * reaching us (ctl).  Both directions are enforced here: OUT policies
	 * drive outbound_table_0 (encrypt/bypass), IN policies drive
	 * inbound_spd_table_0 (RFC 4301 fail-closed: a clear frame matching
	 * an inbound PROTECT/DISCARD policy is dropped, not forwarded). */
	if (sp->dir != R2DP_DIR_OUT && sp->dir != R2DP_DIR_IN)
		return 0;

	p = p4_pol_find(pr, sp);
	if (!p) {
		int ghost = -1;
		/* The OUT SPD table is a WILDCARD keyed on (proto, masked src,
		 * masked dst) only.  A selector that differs from an existing
		 * OUT policy only by port, scope, or host bits inside the
		 * prefix, shares its ACL row, but ctl (sel_eq_d) keys on the
		 * full selector and so a later SP_DEL of either would delete
		 * the row for BOTH (fail-open).  Refuse the new policy before
		 * it is committed; do not alias two selectors into one row.
		 * Don't take a ghost slot or touch any mirror state on this
		 * path -- ctl rolls its own copy back on our error. */
		for (i = 0; i < P4_SP_MAX; i++) {
			struct p4_pol *q = &pr->spd[i];
			if (!q->in_use || q->sp.dir != sp->dir)
				continue;
			if (p4_pol_row_conflicts(&q->sp, sp))
				return -E2BIG;  /* ACL cannot name both selectors */
		}
		for (i = 0; i < P4_SP_MAX; i++)
			if (!pr->spd[i].in_use) { ghost = i; break; }
		if (ghost < 0)
			return -ENOSPC;
		p = &pr->spd[ghost];
		p->sp = *sp;
		p->bound_sl_id = UINT32_MAX;
		/* Do NOT mark in_use before bind: a failed bind must not leave a
		 * ghost policy that wedges later outbound SA ops (ctl rolls its
		 * own copy back on our error, so our mirror must match). */
	} else {
		/* Live update: snapshot the current policy so that, if the bind
		 * or the commit fails, we restore BOTH the selector and the
		 * bound-sa id.  Otherwise a failed PROTECT->BYPASS update would
		 * leave the mirror holding the rejected policy, and the next
		 * outbound rebind would program it -- a fail-open on a policy
		 * ctl still holds. */
		saved_sp = p->sp;
		saved_bound = p->bound_sl_id;
		saved_in_use = p->in_use;
		was_live = 1;
		p->sp = *sp;
	}

	/* Accept whether or not an egress SA exists yet (spmd installs SPD
	 * first; a later SA_ADD rebinds).  The alias check above refuses a
	 * selector the ACL cannot name (-E2BIG); -ENOSPC covers a full mirror
	 * and bind can return -EAFNOSUPPORT/commit errors.  Otherwise accept,
	 * including an unbound PROTECT (fail-closed). */
	if (sp->dir == R2DP_DIR_OUT)
		rc = p4_spd_bind(pr, p);      /* outbound SPD: encrypt/bypass */
	else
		rc = p4_inspd_bind(pr, p);    /* inbound SPD: fail-closed drop */
	if (rc) {
		if (was_live) {
			p->sp = saved_sp;
			p->bound_sl_id = saved_bound;
			p->in_use = saved_in_use;
		} else {
			memset(p, 0, sizeof(*p));   /* drop the new ghost */
		}
		for (unsigned s = 0; s < pr->n_inst; s++)
			rte_swx_ctl_pipeline_abort(pr->inst[s].ctl);
		return rc;
	}

	/* Now that the exact table entry is scheduled, publish it.  Only mark
	 * in_use after we know the whole add succeeded; on a failed commit
	 * (abort_on_fail=1 rolls the table op back) mirror the rollback so our
	 * view matches ctl's, which keeps its policy on error. */
	{
		unsigned s;
		for (s = 0; s < pr->n_inst; s++) {
			rc = rte_swx_ctl_pipeline_commit(pr->inst[s].ctl, 1);
			if (rc)
				break;
		}
		if (rc) {
			if (was_live) {
				p->sp = saved_sp;
				p->bound_sl_id = saved_bound;
				p->in_use = saved_in_use;
			} else {
				memset(p, 0, sizeof(*p));
			}
			P4_LOG("sp_add commit %d; mirror rolled back", rc);
			return rc;
		}
	}
	p->in_use = 1;
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
	/* Tear down every slice.  Always free whatever was allocated, even on a
	 * partial start (the probe calls stop on failure).  `started` is not the
	 * only guard.
	 *
	 * ORDER: stop and join the PRODUCERS (slices) FIRST, then the io thread
	 * last.  The io thread drains every slice's egress rings; if it exits
	 * while slices 1..N-1 still enqueue, those mbufs are abandoned when the
	 * pipeline is freed below.  So clear every slice's running, join them,
	 * and only then stop+join the io thread (which exits once no slice runs). */
	{
		unsigned s;
		for (s = 0; s < pr->n_inst; s++)
			atomic_store_explicit(&pr->inst[s].running, 0, __ATOMIC_RELAXED);
		for (s = 0; s < pr->n_inst; s++) {
			if (pr->inst[s].th_started) {
				pthread_join(pr->inst[s].th, NULL);
				pr->inst[s].th_started = 0;
			}
		}
	}
	if (pr->rx_started) {
		pthread_join(pr->rx_th, NULL);
		pr->rx_started = 0;
	}
	{
		unsigned s;
		for (s = 0; s < pr->n_inst; s++) {
			if (pr->inst[s].ctl)
				rte_swx_ctl_pipeline_free(pr->inst[s].ctl);
			if (pr->inst[s].ipsec)
				rte_swx_ipsec_free(pr->inst[s].ipsec);
			if (pr->inst[s].p)
				rte_swx_pipeline_free(pr->inst[s].p);
			pr->inst[s].ctl = NULL;
			pr->inst[s].ipsec = NULL;
			pr->inst[s].p = NULL;
			pr->inst[s].in0 = pr->inst[s].in1 = NULL;
			pr->inst[s].out0 = pr->inst[s].out1 = NULL;
		}
		if (pr->pool)
			rte_mempool_free(pr->pool);
		pr->pool = NULL;
	}
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

	/* Number of P4 slices (cores).  R2DP_P4_WORKERS=N starts N independent
	 * pipeline replicas, each on its own core -- the NIC-compatible multicore
	 * model.  Default/absent = 1 (the historical single pipeline). */
	{
		const char *w = getenv("R2DP_P4_WORKERS");
			long n = 1;
			if (w) {
				char *end = NULL;
				n = strtol(w, &end, 10);
				/* Refuse empty/non-numeric and <1 exactly like
				 * >MAX: a nonsense worker count must not silently
				 * become 1 (the operator asked for a specific
				 * shard topology; guessing is under-provisioning). */
				if (!end || *end != '\0' || n < 1) {
					P4_LOG("R2DP_P4_WORKERS='%s' refused "
					       "(need 1..%d)", w,
					       R2DP_P4_MAX_INST);
					return -EINVAL;
				}
			}
			if (n > R2DP_P4_MAX_INST) {
				/* Fail closed, do not silently clamp: N slices must map 1:1
				 * to cryptodev queue pairs and to CPU cores, and a request
				 * the box cannot honour (N > MAX_INST, e.g. >8 QPs) must
				 * not quietly run fewer slices than the control plane
				 * thinks it programmed.  A silent clamp under-provisions
				 * the plane while the operator believes N peers exist. */
				P4_LOG("R2DP_P4_WORKERS=%ld refused: max %d", n,
				       R2DP_P4_MAX_INST);
				return -EINVAL;
			}
			pr->n_inst = (uint32_t)n;
	}
	P4_LOG("slices=%u", pr->n_inst);

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

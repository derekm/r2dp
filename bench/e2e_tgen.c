/*
 * e2e_tgen: traffic generator + validating sink for the end-to-end
 * forwarder benchmark (bench/e2e_bench.sh).
 *
 *   gen port (port 0) --plaintext--> r2dp A --ESP--> r2dp B --plaintext--> sink port (port 1)
 *
 * Port 0 transmits IPv4/UDP frames of one size, flows 10.2.t.5 ->
 * 10.1.t.5 for tunnel t (t >= 256: 10.4/10.3, 10.6/10.5, ...) (a burst of 32 per tunnel, tunnels round-robin),
 * each carrying a magic, its sequence number and a byte pattern.  Port 1
 * polls every RX queue and counts a frame as valid only if the inner IP
 * header checksums, the length is what was sent and the magic + pattern
 * check out.  Before measuring it sends IKE-shaped frames (UDP/500)
 * from every B tunnel address into B's inner side; B forwards them clear
 * to A, which learns its next hop for each tunnel peer from them.
 *
 * Per frame size: a saturated run (generator unpaced; loss = accepted by
 * the link but not delivered valid) and a binary search for the highest
 * paced rate whose loss against the offered rate is <= LOSS (default
 * 0.1%) with no invalid frame, each step retried once before it counts
 * as failed.  --loop: ports 0 and 1 are wired to each
 * other (no forwarder), measuring the generator + link ceiling.
 * One JSON line per size on stdout.
 *
 *   e2e_tgen [EAL args] -- --sizes 64,512 --tunnels N --secs S
 *            [--loss 0.001] [--peer-base 203.0.113.1] [--rxq N]
 *            [--rate MPPS]   (one paced trial instead of the search)
 * Sizes are Ethernet frame sizes without FCS (64 = 50-byte IP packet).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_cycles.h>
#include <rte_lcore.h>

#define BURST   32
#define MAXTUN  16384
#define MAGIC   0x52324450u          /* "R2DP" */
#define PL_OFF  (14 + 20 + 8)        /* payload offset in the frame */

static struct rte_mempool *mp;
static unsigned ntun = 1, nrxq = 1, frame;
static double secs = 2, loss_max = 0.001, fixed_mpps;
static uint32_t peer_base;           /* host order: B address of tunnel 0 */
static struct rte_mbuf *tmpl[MAXTUN];

static volatile int run_rx, run_tx;
static volatile uint64_t g_rx, g_valid, g_bad;
static uint64_t g_tx, g_offered;
static double g_rate;                /* pps, 0 = unpaced */

static void
mk_frame(uint8_t *f, unsigned len, uint32_t src, uint32_t dst, uint16_t sport,
    uint16_t dport)
{
	struct rte_ipv4_hdr *ip = (void *)(f + 14);
	struct rte_udp_hdr *u = (void *)(ip + 1);

	memset(f, 0, len);
	f[0] = 0x02; f[5] = 0x01; f[6] = 0x02; f[11] = 0x02; f[12] = 0x08;
	ip->version_ihl = 0x45;
	ip->total_length = rte_cpu_to_be_16((uint16_t)(len - 14));
	ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = src;
	ip->dst_addr = dst;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
	u->src_port = rte_cpu_to_be_16(sport);
	u->dst_port = rte_cpu_to_be_16(dport);
	u->dgram_len = rte_cpu_to_be_16((uint16_t)(len - 14 - 20));
}

static uint8_t
pat(unsigned i)
{
	return (uint8_t)(i * 7 + 3);
}

static int
build_templates(void)
{
	for (unsigned t = 0; t < ntun; t++) {
		struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
		uint8_t *f;
		char s[32], d[32];
		uint32_t sa, da, mg = htonl(MAGIC);

		if (!m || !(f = (uint8_t *)rte_pktmbuf_append(m, (uint16_t)frame)))
			return -1;
		/* tunnel t: 10.(2+2*(t/256)).(t%256).5 -> 10.(1+2*(t/256)).(t%256).5 */
		snprintf(s, sizeof(s), "10.%u.%u.5", 2 + 2 * (t >> 8), t & 255);
		snprintf(d, sizeof(d), "10.%u.%u.5", 1 + 2 * (t >> 8), t & 255);
		inet_pton(AF_INET, s, &sa);
		inet_pton(AF_INET, d, &da);
		mk_frame(f, frame, sa, da, 1024, 9);
		if (frame >= PL_OFF + 8) {   /* (64 B: 22 payload bytes) */
			memcpy(f + PL_OFF, &mg, 4);
			f[PL_OFF + 4] = (uint8_t)t;
			f[PL_OFF + 5] = (uint8_t)(t >> 8);
			for (unsigned i = PL_OFF + 8; i < frame; i++)
				f[i] = pat(i);
		}
		if (tmpl[t])
			rte_pktmbuf_free(tmpl[t]);
		tmpl[t] = m;
	}
	return 0;
}

/* valid: checksummed IPv4 of the sent length with magic + pattern (checked
 * at the head and the tail of the payload) */
static int
valid(const struct rte_mbuf *m)
{
	const uint8_t *f = rte_pktmbuf_mtod(m, const uint8_t *);
	const struct rte_ipv4_hdr *ip = (const void *)(f + 14);
	uint32_t mg;

	if (rte_pktmbuf_data_len(m) < frame || ip->version_ihl != 0x45 ||
	    rte_be_to_cpu_16(ip->total_length) != frame - 14 ||
	    rte_ipv4_cksum(ip) != 0)
		return 0;
	if (frame < PL_OFF + 8)
		return 1;
	memcpy(&mg, f + PL_OFF, 4);
	if (ntohl(mg) != MAGIC ||
	    (unsigned)(f[PL_OFF + 4] | f[PL_OFF + 5] << 8) >= ntun)
		return 0;
	/* Cross-check the claimed tunnel index against the frame's own inner
	 * addresses.  Without this, a dataplane that duplicates a frame onto
	 * another tunnel (or rewrites the payload header) is blessed as
	 * zero-loss at an inflated rate: the magic+index still match.
	 * Tunnel t: src 10.(2+2h).l.5, dst 10.(1+2h).l.5 with h=t>>8, l=t&255. */
	{
		unsigned t = f[PL_OFF + 4] | f[PL_OFF + 5] << 8;
		unsigned h = t >> 8, l = t & 255;
		uint32_t sr = (10u << 24) | ((2 + 2 * h) << 16) | (l << 8) | 5;
		uint32_t dr = (10u << 24) | ((1 + 2 * h) << 16) | (l << 8) | 5;

		if (rte_be_to_cpu_32(ip->src_addr) != sr ||
		    rte_be_to_cpu_32(ip->dst_addr) != dr)
			return 0;
	}
	for (unsigned i = PL_OFF + 8; i < frame && i < PL_OFF + 24; i++)
		if (f[i] != pat(i))
			return 0;
	for (unsigned i = frame > 16 ? frame - 16 : PL_OFF + 8; i < frame; i++)
		if (i >= PL_OFF + 8 && f[i] != pat(i))
			return 0;
	return 1;
}

static int
rx_main(void *arg)
{
	struct rte_mbuf *b[BURST];
	uint64_t rx = 0, ok = 0, bad = 0;

	(void)arg;
	while (run_rx) {
		for (uint16_t q = 0; q < nrxq; q++) {
			uint16_t n = rte_eth_rx_burst(1, q, b, BURST);
			for (uint16_t i = 0; i < n; i++) {
				const uint8_t *f = rte_pktmbuf_mtod(b[i], const uint8_t *);
				rx++;
				/* frames that are not ours (IKE echo etc.) */
				if (rte_pktmbuf_data_len(b[i]) >= 34 && f[23] == IPPROTO_UDP &&
				    f[36] == 0x01 && f[37] == 0xf4) {
					rx--;
				} else if (valid(b[i])) {
					ok++;
				} else {
					bad++;
				}
			}
			rte_pktmbuf_free_bulk(b, n);
		}
		g_rx = rx; g_valid = ok; g_bad = bad;
	}
	g_rx = rx; g_valid = ok; g_bad = bad;
	return 0;
}

/* drain whatever A sends back to the generator side (IKE echo) */
static void
drain0(void)
{
	struct rte_mbuf *b[BURST];
	for (uint16_t q = 0; q < nrxq; q++) {
		uint16_t n;
		while ((n = rte_eth_rx_burst(0, q, b, BURST)) != 0)
			rte_pktmbuf_free_bulk(b, n);
	}
}

/* Transmit for `secs` on port 0 (main lcore): refcount-shared templates,
 * paced to g_rate if set.  Counts offered (generated) and accepted. */
static void
tx_run(void)
{
	uint64_t hz = rte_get_tsc_hz(), t0 = rte_rdtsc(), end = t0 + (uint64_t)(secs * hz);
	uint64_t next = t0, step = g_rate > 0 ? (uint64_t)(BURST * hz / g_rate) : 0;
	uint64_t off = 0, acc = 0;
	unsigned t = 0;
	struct rte_mbuf *b[BURST];

	for (;;) {
		uint64_t now = rte_rdtsc();
		if (now >= end)
			break;
		if (step && now < next) {
			continue;
		}
		next += step;
		for (int i = 0; i < BURST; i++) {
			b[i] = tmpl[t];
		}
		rte_mbuf_refcnt_update(tmpl[t], BURST);
		uint16_t s = rte_eth_tx_burst(0, (uint16_t)(t % nrxq), b, BURST);
		if (s < BURST)
			rte_mbuf_refcnt_update(tmpl[t], (int16_t)-(BURST - s));
		off += BURST;
		acc += s;
		t = (t + 1) % ntun;
		if ((off & 1023) == 0)
			drain0();
	}
	g_offered = off;
	g_tx = acc;
}

struct res { double offered_pps, tx_pps, rx_pps, valid_pps, loss; uint64_t bad; };

static struct res
trial(double rate)
{
	struct res r;
	uint64_t rx0, v0, b0, rx1, v1, b1;

	g_rate = rate;
	rte_delay_ms(200);                 /* let the previous trial drain */
	rx0 = g_rx; v0 = g_valid; b0 = g_bad;
	tx_run();
	rte_delay_ms(300);                 /* in-flight frames land */
	rx1 = g_rx; v1 = g_valid; b1 = g_bad;
	r.offered_pps = g_offered / secs;
	r.tx_pps = g_tx / secs;
	r.rx_pps = (rx1 - rx0) / secs;
	r.valid_pps = (v1 - v0) / secs;
	r.bad = b1 - b0;
	/* loss against what the generator offered: a link that refuses the
	 * generator's frames is loss too */
	r.loss = g_offered ? 1.0 - (double)(v1 - v0) / (double)g_offered : 1;
	if (rate <= 0)                     /* unpaced: every spin "offers" */
		r.loss = g_tx ? 1.0 - (double)(v1 - v0) / (double)g_tx : 1;
	return r;
}

static void
prime(void)
{
	/* IKE-shaped UDP/500 from each B tunnel address to A, into B's inner
	 * side: B passes them clear to A, A learns its next hops */
	for (int rep = 0; rep < 5; rep++) {
		for (unsigned t = 0; t < ntun; t++) {
			struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
			uint8_t *f;
			uint32_t s = htonl(peer_base + t), d;
			if (!m) continue;
			f = (uint8_t *)rte_pktmbuf_append(m, 64);
			if (!f) { rte_pktmbuf_free(m); continue; }
			inet_pton(AF_INET, "192.0.2.1", &d);
			mk_frame(f, 64, s, d, 500, 500);
			if (rte_eth_tx_burst(1, 0, &m, 1) != 1)
				rte_pktmbuf_free(m);
		}
		rte_delay_ms(100);
		drain0();
	}
}

static int
parse_list(char *s, unsigned *v, int max)
{
	int n = 0;
	for (char *p = strtok(s, ","); p && n < max; p = strtok(NULL, ","))
		v[n++] = (unsigned)atoi(p);
	return n;
}

int
main(int argc, char **argv)
{
	unsigned sizes[16] = { 64, 512, 1400, 1514 }, nsz = 4, lc;
	int n = rte_eal_init(argc, argv);
	struct rte_eth_conf conf;

	if (n < 0) { fprintf(stderr, "EAL init failed\n"); return 1; }
	argc -= n; argv += n;
	inet_pton(AF_INET, "203.0.113.1", &peer_base);
	peer_base = ntohl(peer_base);
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--sizes") && i + 1 < argc)
			nsz = (unsigned)parse_list(argv[++i], sizes, 16);
		else if (!strcmp(argv[i], "--tunnels") && i + 1 < argc)
			ntun = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--secs") && i + 1 < argc)
			secs = atof(argv[++i]);
		else if (!strcmp(argv[i], "--loss") && i + 1 < argc)
			loss_max = atof(argv[++i]);
		else if (!strcmp(argv[i], "--rate") && i + 1 < argc)
			fixed_mpps = atof(argv[++i]);
		else if (!strcmp(argv[i], "--rxq") && i + 1 < argc)
			nrxq = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--peer-base") && i + 1 < argc) {
			inet_pton(AF_INET, argv[++i], &peer_base);
			peer_base = ntohl(peer_base);
		}
	}
	if (ntun < 1 || ntun > MAXTUN || rte_eth_dev_count_avail() < 2) {
		fprintf(stderr, "e2e_tgen: need 2 ports and 1..%d tunnels\n", MAXTUN);
		return 2;
	}
	mp = rte_pktmbuf_pool_create("tg", 16383 + (unsigned)ntun, 256, 0, 2048 + 128, rte_socket_id());
	if (!mp) { fprintf(stderr, "mempool\n"); return 1; }
	memset(&conf, 0, sizeof(conf));
	for (uint16_t p = 0; p < 2; p++) {
		if (rte_eth_dev_configure(p, (uint16_t)nrxq, (uint16_t)nrxq, &conf) < 0)
			return 1;
		for (uint16_t q = 0; q < nrxq; q++)
			if (rte_eth_rx_queue_setup(p, q, 1024, 0, NULL, mp) < 0 ||
			    rte_eth_tx_queue_setup(p, q, 1024, 0, NULL) < 0)
				return 1;
		if (rte_eth_dev_start(p) < 0)
			return 1;
	}
	for (int i = 0; i < 100; i++) {          /* memif connect */
		struct rte_eth_link l0, l1;
		if (rte_eth_link_get_nowait(0, &l0) == 0 &&
		    rte_eth_link_get_nowait(1, &l1) == 0 &&
		    l0.link_status && l1.link_status)
			break;
		rte_delay_ms(100);
	}
	run_rx = 1;
	lc = rte_get_next_lcore(-1, 1, 0);
	if (lc >= RTE_MAX_LCORE) { fprintf(stderr, "need 2 lcores\n"); return 2; }
	rte_eal_remote_launch(rx_main, NULL, lc);
	prime();
	setvbuf(stdout, NULL, _IONBF, 0);
	for (unsigned z = 0; z < nsz; z++) {
		struct res sat, best = { 0 }, r;
		double lo, hi;

		frame = sizes[z];
		if (build_templates()) { fprintf(stderr, "templates\n"); return 1; }
		prime();
		if (fixed_mpps > 0) {           /* --rate: one paced trial */
			r = trial(fixed_mpps * 1e6);
			printf("{\"size\":%u,\"tunnels\":%u,\"rate_mpps\":%.3f,"
			    "\"tx_mpps\":%.3f,\"valid_mpps\":%.3f,\"gbps\":%.3f,"
			    "\"loss\":%.5f,\"bad\":%llu}\n", frame, ntun, fixed_mpps,
			    r.tx_pps / 1e6, r.valid_pps / 1e6,
			    r.valid_pps * frame * 8 / 1e9, r.loss,
			    (unsigned long long)r.bad);
			continue;
		}
		sat = trial(0);
		/* zero-loss search: between 0 and the saturated offered rate */
		lo = 0; hi = sat.tx_pps;
		for (int it = 0; it < 9 && hi > 1000; it++) {
			double mid = it == 0 ? sat.valid_pps : (lo + hi) / 2;
			r = trial(mid);
			/* one retry: on a shared host a single descheduling of a
			 * poller overflows a 1024-slot ring; a rate that is really
			 * too high fails both */
			if (r.loss > loss_max || r.bad)
				r = trial(mid);
			if (r.loss <= loss_max && r.bad == 0) {
				lo = mid;
				best = r;
			} else {
				hi = mid;
			}
			if (it > 0 && hi - lo < hi * 0.02)
				break;
		}
		printf("{\"size\":%u,\"tunnels\":%u,"
		    "\"sat_tx_mpps\":%.3f,\"sat_valid_mpps\":%.3f,"
		    "\"sat_gbps\":%.3f,\"sat_loss\":%.4f,\"sat_bad\":%llu,"
		    "\"nl_mpps\":%.3f,\"nl_gbps\":%.3f,\"nl_loss\":%.5f}\n",
		    frame, ntun, sat.tx_pps / 1e6,
		    sat.valid_pps / 1e6, sat.valid_pps * frame * 8 / 1e9, sat.loss,
		    (unsigned long long)sat.bad, best.valid_pps / 1e6,
		    best.valid_pps * frame * 8 / 1e9, best.loss);
	}
	run_rx = 0;
	rte_eal_mp_wait_lcore();
	return 0;
}

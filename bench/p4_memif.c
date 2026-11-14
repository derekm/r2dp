/* p4_memif: drive a real frame through the P4/SWX forwarder's data plane and
 * show it is bridged end-to-end.
 *
 * Topology (single forwarder, memif legs):
 *   this probe port 1 (inner/client) ==memif== [inner] r2dp-p4 [outer] ==memif== probe port 0
 *          send plaintext IPv4                     |  outbound SP: protect/bypass
 *                                                                  |  egress routed to outer
 *   probe port 0 (outer/client) <-- the forwarder's outer leg.
 *
 * The forwarder is launched with:
 *   --vdev net_memif0,role=server,socket=OUTER.sock   (port 0 = wire/outer)
 *   --vdev net_memif1,role=server,socket=INNER.sock   (port 1 = inner/plaintext)
 * This probe is the memif CLIENT on both (it must come up after the forwarder).
 *
 * It sends one plaintext IPv4/UDP frame on port 1 (inner side) and then
 * polls port 0 (outer side) for an egressed frame, printing how many bytes
 * and the outer ethertype.  A non-zero egress RX proves I/O rings -> pipeline
 * run -> next_hop -> output ring -> ethdev bridge actually moves bytes, and
 * that the outbound default (spd_bypass) or a programmed SPD action reached
 * egress.  For a negative control, send on port 1 with no forwarder: nothing
 * egresses port 0.
 *
 * Usage: p4_memif --vdev net_memif...,role=client,socket=... [EAL]
 *        (the two --vdev give port 0 = outer, port 1 = inner)
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

#define BURST 32

static struct rte_mempool *mp;

static int
mk_frame(struct rte_mbuf *m)
{
	uint8_t *f = (uint8_t *)rte_pktmbuf_append(m, 64);
	struct rte_ipv4_hdr *ip;
	struct rte_udp_hdr *u;
	uint32_t s, d;

	if (!f)
		return -1;
	memset(f, 0, 64);
	f[0] = 0x02; f[5] = 0x01; f[6] = 0x02; f[11] = 0x02; f[12] = 0x08; f[13] = 0x00;
	ip = (struct rte_ipv4_hdr *)(void *)(f + 14);
	ip->version_ihl = 0x45;
	ip->total_length = rte_cpu_to_be_16(50);
	ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_UDP;
	inet_pton(AF_INET, "192.0.2.1", &s);
	inet_pton(AF_INET, "192.0.2.2", &d);
	ip->src_addr = s;
	ip->dst_addr = d;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
	u = (struct rte_udp_hdr *)(void *)(ip + 1);
	u->src_port = rte_cpu_to_be_16(1024);
	u->dst_port = rte_cpu_to_be_16(9);
	u->dgram_len = rte_cpu_to_be_16(8);
	return 0;
}

static void
rx_drain(uint16_t port, const char *tag)
{
	struct rte_mbuf *b[BURST];
	uint16_t n = rte_eth_rx_burst(port, 0, b, BURST);
	for (uint16_t i = 0; i < n; i++) {
		const uint8_t *f = rte_pktmbuf_mtod(b[i], const uint8_t *);
		uint16_t et = (uint16_t)((f[12] << 8) | f[13]);
		uint16_t len = rte_pktmbuf_data_len(b[i]);
		printf("%s: RX %u bytes, ethertype 0x%04x\n", tag, len, et);
		rte_pktmbuf_free(b[i]);
	}
}

int
main(int argc, char **argv)
{
	int n;
	struct rte_eth_conf conf;
	struct rte_mbuf *tx;
	uint16_t sent, received = 0;

	n = rte_eal_init(argc, argv);
	if (n < 0) { fprintf(stderr, "EAL init failed\n"); return 1; }
	argc -= n; argv += n;
	if (rte_eth_dev_count_avail() < 2) {
		fprintf(stderr, "p4_memif: need 2 ports (outer=0, inner=1)\n");
		return 2;
	}
	mp = rte_pktmbuf_pool_create("pm", 1024, 256, 0, 2048 + 128,
				     rte_socket_id());
	if (!mp) { fprintf(stderr, "mempool\n"); return 1; }
	memset(&conf, 0, sizeof(conf));
	for (uint16_t p = 0; p < 2; p++) {
		if (rte_eth_dev_configure(p, 1, 1, &conf) < 0 ||
		    rte_eth_rx_queue_setup(p, 0, 512, 0, NULL, mp) < 0 ||
		    rte_eth_tx_queue_setup(p, 0, 512, 0, NULL) < 0 ||
		    rte_eth_dev_start(p) < 0) {
			fprintf(stderr, "port %u setup failed\n", p);
			return 1;
		}
	}
	/* wait for memif link-up on both legs */
	for (int i = 0; i < 100; i++) {
		struct rte_eth_link l0, l1;
		rte_eth_link_get_nowait(0, &l0);
		rte_eth_link_get_nowait(1, &l1);
		if (l0.link_status && l1.link_status)
			break;
		rte_delay_ms(100);
	}

	tx = rte_pktmbuf_alloc(mp);
	if (!tx) { fprintf(stderr, "alloc\n"); return 1; }
	if (mk_frame(tx) < 0) { fprintf(stderr, "frame\n"); return 1; }

	printf("sending on port 1 (inner), polling port 0 (outer)...\n");
	sent = rte_eth_tx_burst(1, 0, &tx, 1);
	if (sent != 1)
		printf("port 1 tx returned %u\n", sent);
	rte_delay_ms(500);
	rx_drain(0, "outer");
	printf("done\n");
	return 0;
}

/*
 * fwd/dpdk_port.c -- ethdev setup for the DPDK data plane.
 *
 * Every ethdev call's own return is propagated: those APIs return a
 * negative errno directly and do not promise to set rte_errno, so a failed
 * stage must never turn into success or a stale diagnosis (PORTIO P1).
 */
#ifdef R2DP_HAVE_DPDK

#include "dpdk_int.h"

static int
port_fail(uint16_t port, const char *stage, int q, int ret)
{
	if (ret >= 0)
		ret = -EIO;         /* never let a failed stage read as success */
	if (q >= 0)
		fprintf(stderr, "r2dp-fwd: port %u %s queue %d failed: %s\n",
		    port, stage, q, rte_strerror(-ret));
	else
		fprintf(stderr, "r2dp-fwd: port %u %s failed: %s\n",
		    port, stage, rte_strerror(-ret));
	return ret;
}

/* nq RX and nq TX queues (net_tap insists they match): one of each per
 * worker.  Returns 0 or a negative errno naming the failing stage. */
int
dp_port_init(struct dpdk_priv *d, uint16_t port, unsigned ntxq)
{
	struct rte_eth_conf conf;
	struct rte_eth_dev_info dev_info;
	uint16_t nrxq = (uint16_t)ntxq;
	int ret;

	if (port >= RTE_MAX_ETHPORTS || !rte_eth_dev_is_valid_port(port))
		return port_fail(port, "lookup", -1, -ENODEV);
	if (ntxq == 0 || ntxq > UINT16_MAX)
		return port_fail(port, "queue count", -1, -EINVAL);
	memset(&conf, 0, sizeof(conf));
	ret = rte_eth_dev_info_get(port, &dev_info);
	if (ret < 0)
		return port_fail(port, "dev_info_get", -1, ret);
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
	if (ntxq > dev_info.max_tx_queues || nrxq > dev_info.max_rx_queues) {
		fprintf(stderr, "r2dp-fwd: port %u has %u rx / %u tx queues, "
		    "need %u\n", port, dev_info.max_rx_queues,
		    dev_info.max_tx_queues, ntxq);
		return -EINVAL;
	}
	/* No RSS.  A hash onto a queue is not the worker tun_owner()
	 * assigned, so it would cross-post every packet.  Queue q is
	 * worker q.  The sender places a tunnel on that queue. */
	ret = rte_eth_dev_configure(port, nrxq, (uint16_t)ntxq, &conf);
	if (ret < 0)
		return port_fail(port, "configure", -1, ret);
	for (uint16_t q = 0; q < nrxq; q++) {
		ret = rte_eth_rx_queue_setup(port, q, 1024,
		    rte_eth_dev_socket_id(port), NULL, d->pool);
		if (ret < 0)
			return port_fail(port, "rx setup", q, ret);
	}
	for (uint16_t q = 0; q < (uint16_t)ntxq; q++) {
		ret = rte_eth_tx_queue_setup(port, q, 1024,
		    rte_eth_dev_socket_id(port), NULL);
		if (ret < 0)
			return port_fail(port, "tx setup", q, ret);
	}
	ret = rte_eth_dev_start(port);
	if (ret < 0)
		return port_fail(port, "start", -1, ret);
	/* Promiscuous mode is optional: a PMD without it (or one already
	 * filtering on our MAC) still forwards traffic addressed to us. */
	ret = rte_eth_promiscuous_enable(port);
	if (ret < 0 && ret != -ENOTSUP)
		fprintf(stderr, "r2dp-fwd: port %u promiscuous enable: %s "
		    "(continuing)\n", port, rte_strerror(-ret));
	return 0;
}

#endif /* R2DP_HAVE_DPDK */

/*
 * dp_port: fwd/dpdk_port.c propagates each ethdev call's own error (PORTIO
 * P1).  The ethdev API returns negative errnos directly and leaves
 * rte_errno alone, so with rte_errno at 0 -- or at an unrelated value -- a
 * failing stage must still return its exact error, never 0.  Uses the
 * net_null vdev; no NIC needed.
 */
#include "dpdk_int.h"

static int fails;
#define CHECK(c, msg) do { if (c) printf("ok   %s\n", msg); \
	else { printf("FAIL %s\n", msg); fails++; } } while (0)

int
main(void)
{
	char *ea[] = { "dp_port", "--no-huge", "--no-pci", "-m", "128",
	    "--no-shconf", "--vdev=net_null0", "--log-level=1", NULL };
	struct dpdk_priv *d;
	uint16_t port;
	int seeds[2] = { 0, EPERM };

	setvbuf(stdout, NULL, _IONBF, 0);
	/* INIT I1: the pool covers worst-case retention for every -n */
	{
		int ok = 1;

		for (unsigned p = 1; p <= 2; p++)
			for (unsigned n = 1; n <= 8; n++) {
				unsigned lc = n + 1;
				uint64_t need = (uint64_t)p * n * (DP_RX_DESC + DP_TX_DESC) +
				    (uint64_t)n * 2 * DP_RING_SZ +
				    (uint64_t)n * (DP_QP_DESC + 4 * BURST_SZ) +
				    (uint64_t)lc * MEMPOOL_CACHE;

				if (dp_mbuf_pool_size(p, n, lc) <= need ||
				    dp_mbuf_pool_size(p, n, lc) < MEMPOOL_SIZE)
					ok = 0;
			}
		CHECK(ok, "mbuf pool exceeds worst-case retention for 1..8 workers, 1..2 ports");
		CHECK(dp_mbuf_pool_size(2, 8, 9) > 2u * 8 * DP_RX_DESC,
		    "-n 8, two ports: RX arming alone no longer drains the pool");
	}
	if (rte_eal_init(8, ea) < 0 ||
	    rte_eth_dev_get_port_by_name("net_null0", &port) != 0) {
		if (getenv("R2DP_REQUIRE_DPDK")) { puts("DPDK setup FAILED"); return 1; }
		puts("SKIP: EAL/net_null"); return 77;
	}
	d = calloc(1, sizeof(*d));
	if (!d) return 1;
	d->pool = rte_pktmbuf_pool_create("dp_port_mb", 4096, 0, 0,
	    RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	if (!d->pool) { puts("pool FAILED"); return 1; }

	for (int i = 0; i < 2; i++) {
		char m[160];
		int r;

		rte_errno = seeds[i];
		r = dp_port_init(d, RTE_MAX_ETHPORTS - 1, 1);
		snprintf(m, sizeof(m), "rte_errno=%d: absent port -> -ENODEV", seeds[i]);
		CHECK(r == -ENODEV, m);

		rte_errno = seeds[i];
		r = dp_port_init(d, port, UINT16_MAX);
		snprintf(m, sizeof(m), "rte_errno=%d: queue-limit rejection -> -EINVAL", seeds[i]);
		CHECK(r == -EINVAL, m);

		rte_errno = seeds[i];
		r = dp_port_init(d, port, 2);
		snprintf(m, sizeof(m), "rte_errno=%d: 2-queue port starts", seeds[i]);
		CHECK(r == 0, m);

		/* configure on a started port: ethdev returns -EBUSY itself */
		rte_errno = seeds[i];
		r = dp_port_init(d, port, 2);
		snprintf(m, sizeof(m), "rte_errno=%d: configure failure -> its own -EBUSY (got %d)",
		    seeds[i], r);
		CHECK(r == -EBUSY, m);

		/* RX setup without a pool: ethdev returns -EINVAL itself */
		CHECK(rte_eth_dev_stop(port) == 0, "port stopped");
		{
			struct rte_mempool *mp = d->pool;

			d->pool = NULL;
			rte_errno = seeds[i];
			r = dp_port_init(d, port, 2);
			d->pool = mp;
		}
		snprintf(m, sizeof(m), "rte_errno=%d: rx setup failure -> its own -EINVAL (got %d)",
		    seeds[i], r);
		CHECK(r == -EINVAL, m);
	}
	rte_eth_dev_stop(port);
	rte_eth_dev_close(port);
	rte_mempool_free(d->pool);
	free(d);
	rte_eal_cleanup();
	if (fails) { printf("dp_port: %d failures\n", fails); return 1; }
	puts("dp_port: OK");
	return 0;
}

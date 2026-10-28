# r2dp DPDK forwarder — load-test & performance report

**Date:** 2026-10-27 · **Box:** Fedora 45, i7-8700 (6C/12T @ 3.2 GHz), 12 DPDK lcores
**Forwarder:** `feat/multicore-dpdk` branch — N-worker run-to-completion + software
distributor + AES-NI (IPSec-MB) PMD. Build OK, all data-plane tests green
(gcm_kat PASS, dp_path OK, dp_sa OK).

## How to run (reproducer)
```
python3 bench/lab/gen_lab_conf.py          # N initiator configs + lab.manifest
sudo NINIT=4 NWORKERS=4 bash bench/lab/lab_up.sh        # bring up
sudo bash bench/lab/lab_spread.sh          # concurrent socat-flood spread
sudo timeout 40 bash /tmp/single_flow.sh   # single-flow ceiling
```
The ESP generator matters: XFRM SAs are per-flow selectors, so a flooder must
match the SA's flow or it never encrypts (clear_outer drop, esp=0). socat
UDP sink on B + python sendto on the SA's port is the reliable generator.

## Results (measured on real runs)

| Metric | Value | Note |
|---|---|---|
| Single-flow (full tap path) | ~0.89 Gbps (python sender) · ~1.5 Gbps (iperf3) | tap user↔kernel crossing is the ceiling |
| Concurrent N-flow | 3 workers engaged, +212K/+246K/+232K esp/6s = ~115K pps ~1.03 Gbps | distributor spreads flows across cores |
| **Internal data-plane ceiling** | enc 456 cyc/pkt (~7 Mpps, 79 Gbps/core) · dec 565 cyc | `bench/fwd_bench`, zero tap I/O |
| Internal × 4 workers | ~28 Mpps / ~300 Gbps | ~100× the tap cap → data plane is NOT the limit |
| Idle CPU | ~500% (4 workers + distributor, busy-poll) | run-to-completion with no backoff |

## Headline finding
The forwarder's **data plane is ~2 orders of magnitude faster than the lab can
deliver** (~300 Gbps internal vs ~1.5 Gbps through `net_tap`). The bottleneck is
the tap's per-packet user↔kernel crossing (AF_PACKET/SKB copy), exactly as kernel
XFRM only beats it by never crossing a user-space tap. The distributor fix
already achieves balanced multi-core worker engagement (the real architectural
win); aggregate single-flow stays tap-bound on this box.

## Next steps / open items
- **A (per-worker inner-tap fan-out)** is implemented and unit-tested in
  `fwd/dp_dpdk.c` (`inner_ports[]`, `worker_inner_tx`, broadened distributor) +
  `lab_fanout.sh` topology, but the aggregate-lift over 1.5G is **not yet
  quantified** (fan-out iperf hit the SA-selector wall; the shared-front
  becomes the next bottleneck anyway).
- Idle power: add `rte_pause()`/sleep backoff on the empty-poll path.
- Real NIC (RSS/DMA) is the genuine fix for >1.5G end-to-end.

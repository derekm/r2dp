# r2dp benchmarks

Two benchmarks, one entry point:

- **fwd_bench**: the production `esp_outbound` / `esp_inbound` code in a
  tight loop on one (or N) lcores with a crypto PMD, no NICs: cycles/packet
  and Mpps per inner packet size and tunnel count.
- **e2e_bench**: real packet I/O. A traffic generator and validating sink
  (`e2e_tgen`) drives two `r2dp-fwd` processes over DPDK memif links
  (plaintext → A encrypts → ESP → B decrypts → plaintext, every packet's
  bytes checked). It reports the saturated rate and a binary-searched
  zero-loss rate (loss ≤ `LOSS`).

## Quick start

```sh
# deps: DPDK >= 22.11 dev files (libdpdk-dev or a source install with
# pkg-config), meson, ninja, python3; optional intel-ipsec-mb for aesni_mb
bench/run.sh            # full sweep, a few minutes on 8 CPUs
bench/run.sh --quick    # ~1 minute smoke
```

`run.sh` configures `build-bench` (release, DPDK enabled) if it does not
exist, builds, records the environment, runs both sweeps and writes
`bench/results/<UTC time>/`:

| file | contents |
|---|---|
| `env.json` | git sha (+dirty), CPU model/flags, CPUs used, governor, kernel, DPDK version, compiler, PMD, hugepages |
| `fwd_w<N>.json` | raw fwd_bench results per worker count |
| `e2e.jsonl` | one raw e2e_bench line per (workers, tunnels, size), incl. both forwarders' counter deltas |
| `summary.csv`, `summary.md` | one row per measurement: Mpps, Gbps, cycles/pkt, loss |
| `*.log` | each run's full output |

With an existing build dir: `meson compile -C BUILD bench`, or
`BUILD=BUILD bench/run.sh --no-build`.

## Knobs (environment)

| variable | default | meaning |
|---|---|---|
| `SIZES` | `64,512,1400` | fwd_bench inner IPv4 sizes |
| `TUNNELS` | `1,65,201` | fwd_bench tunnel counts (up to 100000) |
| `WORKERS` | `1` | fwd_bench worker lcores (list) |
| `RUNS` | `5` | fwd_bench runs per point (median) |
| `E2E_SIZES` | `64,512,1400` | e2e Ethernet frame sizes (≤ 1456: the forwarder does not fragment, and an ESP packet over the outer port's 1500 MTU is dropped as `too_big`) |
| `E2E_TUNNELS` | `1,1000` | e2e tunnel counts (up to 16384) |
| `E2E_WORKERS` | `1,2` | workers per forwarder (W > 1 adds a dispatcher lcore) |
| `SECS`, `LOSS` | `2`, `0.001` | seconds per trial, zero-loss threshold |
| `PMD` | `auto` | `aesni_mb` if the PMD is installed, else `openssl` |
| `HUGE` | `auto` | hugepages when ≥ 3.5 GB are free, else `--no-huge` |
| `CPUS` | all online | CPU list the sweep may use |
| `BUILD`, `OUT` | `build-bench`, `bench/results/<time>` | build and result dirs |

CPU placement for e2e is in list order: generator tx, rx, then forwarder A's
workers (+ dispatcher), B's, then one CPU for the (idle) control threads.
A point that needs more CPUs than `CPUS` has is skipped and said so. W
workers need `2 + 2·(W+1)` CPUs (W = 1: 4), plus one for the control
threads; without that spare CPU the control threads share the last
forwarder CPU, and the zero-loss search then mostly measures their
descheduling (the saturated rate stays meaningful).

For comparable numbers: pin to one NUMA node's physical cores (no SMT
siblings: `CPUS=` from `lscpu -e`), set the `performance` governor, and
keep the box otherwise idle. `env.json` records what was used.

## Real NICs

The benchmarks above need no NIC. To measure `r2dp-fwd` on hardware, run
it between two ports and drive it with an external generator (TRex,
pktgen-dpdk, or `e2e_tgen` on a second host):

```sh
# hugepages + vfio-pci (as root)
echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
modprobe vfio-pci
dpdk-devbind.py -b vfio-pci 0000:3b:00.0 0000:3b:00.1   # inner, outer
# 4 workers + dispatcher on cores 2-6 of the NIC's NUMA node
build-bench/fwd/r2dp-fwd -s /run/r2dp.sock -n 4 --lcores '0@1,1@2,2@3,3@4,4@5,5@6' \
    -a 0000:3b:00.0 -a 0000:3b:00.1 --vdev=crypto_aesni_mb0
```

With several workers each port gets one RX and one TX queue per worker;
on NICs with RSS the RX queues are spread by RSS over IPv4 (+UDP for
NAT-T) and the dispatcher lcore polls them all and hands each packet to
the worker that owns its SA (one SA stays on one worker by design:
per-SA ordering, replay and sequence state). The generator must vary the
inner addresses (and, outer side, the tunnel peers/SPIs) so load spreads
over workers. The dispatcher is one core; past its rate add forwarders
rather than workers. Install
tunnels with `r2dpctl` as in `bench/e2e_bench.sh` (or via iked). Check
`kill -USR1 <pid>` counters for `tx_full` / per-reason drops when the
measured rate is below expectation.

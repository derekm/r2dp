# r2dp — external dataplane control protocol for racoon2

r2dp lets racoon2's IKE daemon (`iked`) and policy daemon (`spmd`) drive an
**external forwarder** — e.g. a standard DPDK IPsec app, or a P4/SWX soft
switch — instead of the kernel.  racoon2 only needs a small backend
(`--with-km-backend=r2dp`); the forwarder is a separate project that speaks a
PF_KEY-shaped protocol over a unix socket.

    iked / spmd ──(rcpfk_* ABI)── if_r2dp.c ──(r2dp, SOCK_SEQPACKET)── forwarder (engine)

## Status
M0 and M1 are done; parts of M2 are in (ESN, NAT-T, lifetimes with EXPIRE,
replay windows up to 1024).  `r2dp-fwd` runs one of **three** data planes
behind the same control socket:

- **DPDK** (`--dp dpdk`, default): `rte_ipsec`, AES-GCM-16, IPv4 tunnel, `-n`
  workers with each tunnel pinned to one of them.
- **Kernel XFRM** (`--dp kernel`): the kernel's ESP stack.
- **P4/SWX** (`--dp p4`): a compiled P4 program (`p4/r2dp.p4`, from p4c's
  `examples/ipsec.p4`) run on DPDK's software pipeline (`rte_swx_pipeline` +
  the `rte_swx_ipsec` extern).  Built with `-Denable_p4=enabled`; loads
  `p4/r2dp.out` by default (override `$R2DP_P4_SPEC`).

The DPDK and kernel engines interoperate with an independent ESP implementation
in CI.  See `COVERAGE.md` for what is verified and what is not, `MILESTONES.md`
for the plan, and the **P4 / SWX backend** section below for the P4-specific
state (proven on the lab box, not yet in CI).

With `-n` > 1, the sender is expected to place each tunnel on its owning
worker's RX queue.  ESP that arrives on another worker's queue is
cross-posted to the owner and can trail that SA's other packets by about
one burst (128 packets); give such SAs a replay window of at least that,
or in-window packets may be dropped as replays.  The stats dump
(`SIGUSR1`) counts these frames as `misplaced`.

## Layout
| path | what |
|---|---|
| `include/r2dp/proto.h` | the wire contract (algorithms = IANA IKEv2 IDs, protocols = IP proto numbers) |
| `include/r2dp/client.h`, `libr2dp/` | transport, validation, address helpers (client + server side) |
| `fwd/` | `r2dp-fwd`: control server (`ctl.c`) and data planes: DPDK (`dp_dpdk.c` ports/workers, `dpdk_sad.c` SA table, `dpdk_spd.c` policy/ACL, `dpdk_esp.c` ESP path, `dpdk_stats.c`), kernel XFRM (`dp_xfrm.c`), or P4/SWX (`dp_p4.c`, gated by `-Denable_p4`) |
| `p4/` | the P4 program (`r2dp.p4`), its compiled spec (`r2dp.out`, generated with standalone `p4c-dpdk --arch pna`), and `PLAN.md` (milestones + §8 limit history) |
| `bench/fwd_bench.c` | ESP path cycles/pkt and Mpps (sizes, tunnel counts, `--workers N`, `--json`); DPDK dataplane ceiling with no NICs |
| `bench/e2e_bench.sh` | end-to-end Gbps/Mpps through two `r2dp-fwd` over memif (`W`, `NTUN` up to 1000, `NATT`, `SIZES`) |
| `bench/p4_bench.sh` | side-by-side P4 vs DPDK ESP throughput on root net_tap (the shared I/O path; both engines) |
| `tools/mockfwd.c` | `r2dp-mockfwd`: protocol-faithful forwarder with no dataplane |
| `patches/racoon2-r2dp-backend.patch` | applies to racoon2 `93e3511` (pre-r2dp base): the r2dp backend, generated from derekm/racoon2 `feat/r2dp-km-backend` @ `baf7094` (`git diff 93e3511 baf7094`) |
| `tests/` | protocol/client: `test_proto`, `test_mock`, `shim_contract` (spin `r2dp-mockfwd`); control server: `ctl_unit`, `ctl_poll`, `smoke_fwd`; data plane (DPDK, crypto_openssl vdev): `gcm_kat`, `dp_sa`, `dp_path` (encrypt→decrypt round trip + policy dispositions), `dp_mt` (concurrent workers on shared SAs), `nh_tab` (next-hop table: growth from 8 to 10000 peers under concurrent lookups, allocation failure during growth); interop: `tests/e2e/fwd_e2e.sh`; pure logic: `sel_test`, `nh_test` |
| `build.sh` | deps / check / build / test / sanitize / e2e / milestones |

## Quick start
    meson setup build && meson compile -C build && meson test -C build

Or via the helper script:
    ./build.sh deps -m 0                 # or: ./build.sh check -m 0
    ./build.sh test -m 0 --racoon2 /path/to/racoon2     # unit + contract tests
    sudo ./build.sh e2e --racoon2 /path/to/racoon2      # clean clone + patch + build + IKEv2 over veth

The racoon2 checkout passed to `--racoon2` is only read (the e2e flow works on a
scratch clone). Run the daemons against a forwarder with `R2DP_SOCK=<path>`
(default `/run/r2dp/r2dp.sock`) and optionally `R2DP_ROLE=iked|spmd`.

> If the scripts lost their executable bit (e.g. after a download/unzip):
> `chmod +x build.sh tests/e2e/*.sh`, or run them as `bash build.sh ...`.

## P4 / SWX backend

`--dp p4` runs the compiled P4 program `p4/r2dp.p4` on DPDK's software
pipeline (`rte_swx_pipeline`, codegen → `.so` → `build_from_lib`) with
the `rte_swx_ipsec` extern (AES-GCM-16, IPv4 tunnel).  `p4/r2dp.out` is the
compiled spec (regenerate with standalone `p4c-dpdk --arch pna`, not the
`p4c` driver).  Build the backend with `-Denable_p4=enabled`; this code
resides on the `p4-backend` branch and is not on `origin/main`.

**What works (verified on the `.165` lab box, root net_tap):**
- SAD/SPD control via the same socket; framed ESP encrypt **and** decrypt
  round-trip (clear → ESP on the outer leg, and ESP → restored plaintext on
  the inner leg).
- SPD is a **wildcard (ternary)** table on `(protocol, src, dst)` with
  prefix/ANY selectors and per-rule priority (`/32` PROTECT beats `/24` ANY
  BYPASS; `10/8` inner routing).
- First-spec limits all resolved: IKE/ARP clear-forward, NAT-T zero-marker
  demux, bad-ICV drop at the extern, and the SPD prefix/ANY limit above.

**Measured throughput** (`bench/p4_bench.sh`, i5-6500T 4-core,
`crypto_openssl0`, 64B): ~132K pps through the shared net_tap — the tap I/O
crossing is the wall, not the data plane.  A tap-free P4 measurement
(`R2DP_P4_BENCH=1`; the worker injects plaintext directly into the pipeline
rings, no ethdev) shows the real SWX+crypto cost: **~1.00 Mpps / ~2484
cyc/pkt** at 64B on `.165` — about 8× the tap figure.  P4 runs one SWX
pipeline instance on the box; a multicore P4 layout (multiple pipeline
instances straddling traffic by RSS/hash) is the path to scaling aggregate
throughput.

DPDK tap-free numbers below come from `bench/fwd_bench --json` runs captured
in `bench/curves_data.json` (regenerate with `bench/curves.py plot`); both
crypto PMDs default to **8 queue pairs**, so a cryptodev used for more than
8 workers must be created with `max_nb_queue_pairs=<n>` and the code ceiling
raised with `dp_max_wk` (= `-DDP_MAX_WK=`).

| box / PMD | enc W=1 | enc W=11 | per-worker cyc W=1 → W=11 |
|---|---|---|---|
| .165 openssl | 2.94 Mpps | (4-core: 3 workers) | 850 → 994 |
| .179 openssl | 4.34 Mpps | 15.93 Mpps | 736 → 2239 |
| .179 aesni_mb | 8.04 Mpps | 28.47 Mpps | 397 → 1243 |

Aggregate throughput scales roughly linearly to 11 workers (`nw+1` lcores);
per-worker `enc cyc/pkt` rises with contention, so the efficiency panel in
`curves.png` plots the bench's own column, not an aggregate reciprocal.
`r2dp-fwd` (unlike `fwd_bench`) refuses to start a dataplane that cannot
serve `-n`: if the cryptodev has fewer queue pairs than requested it prints
the fix and drops to control-only only for `-ENODEV`/no-DPDK-build — an
over-request is a config error, not a silent clamp.  Note that even after
SA_ADD/SP_ADD succeed, a control-only or under-provisioned forwarder will
accept policy but not move ESP, so `-n` must match the device.

**Known open points (current state):**
- `sa_set_hard_bytes` / `sa_set_hard_time` are unset (NULL) on the P4 backend,
  so byte/time hard-lifetime enforcement is control-side (ctl) only, not
  in-datapath as on DPDK.
- Two OUT policies that would share one ACL row — same `(proto, masked src,
  masked dst)`, differing only by port, scope, or host-bits — are rejected
  (`-E2BIG`) because the table cannot name them separately.  Port-scoped SPD
  (e.g. UDP/500 vs UDP/4500 on one prefix) is therefore not expressible.
- The lab runs on root `net_tap` (memif does not materialize on `.165`);
  `bench/p4_bench.sh` drives both engines through that shared I/O path, and
  `R2DP_P4_BENCH=1` measures the P4 data plane tap-free.
- Not yet wired into CI (DPDK/kernel engines are; P4 is lab-proven only).

## Provenance / reconstruction

This repo was stood up from the upstream prototype's `r2dp-claude.zip` (Telegram,
2026-10-24), which shipped `proto.h`, `mockfwd.c`, and the racoon2 backend
patch but **not** `client.h`, `libr2dp/`, or `tests/` (those were listed in
his README as empty dirs). The missing pieces were **reconstructed from the
`proto.h` contract and the `client.h` call-sites** in `shim/if_r2dp.c`
(racoon2 backend) and `tools/mockfwd.c`:

- `include/r2dp/client.h` — the full client/server API (connect/listen/accept,
  send/recv, hello/caps, message accessors, address helpers).
- `libr2dp/libr2dp.c` — transport + validation + address conversion.
- `meson.build` build system and the three M0 tests (`test_proto`,
  `test_mock`, `shim_contract`) with GitHub Actions CI (gcc + clang build/test,
  plus ASan/UBSan). See `ORIGIN.md` for the exact zip provenance.


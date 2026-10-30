# r2dp milestone map

Each milestone is gated by `-Dmilestone=N` (`./build.sh --milestone N`).
Every milestone has an exit gate that must pass before the next starts.
Deps listed are *added* at that milestone; earlier ones carry forward.

## M0 — Contract, client lib, mock forwarder, racoon2 shim  ✅ DONE
- **Built**: `include/r2dp/proto.h` (full wire contract, layout-asserted), `libr2dp/` (transport, validation, address helpers; client + server side), `tools/mockfwd.c` (`r2dp-mockfwd`: kernel-like in-memory SAD/SPD, no DPDK), `shim/if_r2dp.c` + `patches/racoon2-r2dp-backend.patch` (new racoon2 backend `--with-km-backend=r2dp --with-r2dp=PREFIX`).
- **Deps**: C compiler, meson, ninja, pkg-config. racoon2 build: autoconf/automake/libtool/bison/flex/libssl-dev/libpcap-dev. e2e: root, iproute2, iputils-ping.
- **Exit gate — met** (reproduce: `./build.sh e2e --racoon2 <racoon2 checkout>`; ~80 s):
  - `test_proto` (validation, address round-trips), `test_mock` (full SA/SP protocol incl. EEXIST/ENOENT, keys withheld by default), `shim_contract` (the real `rcpfk_*` API incl. `WAITREPLY` scratch routing, ESN/NAT-T/selector fidelity, refusals) — also clean under ASan/UBSan.
  - Patch applies cleanly to pristine upstream (`2fd758a`): 52 glue lines + one new 700-line file; `iked/` and `spmd/` untouched.
  - Two real racoon2 stacks (spmd+iked) in separate netns complete IKEv2 over a veth; each stack's forwarder received HELLO, SPD installs + `SP_DUMP`, forwarder-allocated `GETSPI`, and `SA_ADD`/`SA_UPDATE` for AES-GCM-16 ESP in tunnel mode with a tunnel SP in each direction.
- **Not covered at M0** (don't assume): ESN and NAT-T over a real exchange (only at contract level), rekey/lifetime expiry (the mock never emits `EXPIRE`), IPv6, transport mode, `ACQUIRE`, forwarder restart/resync.

### Findings from the M0 run that shape M1+
1. **`reqid` is 0 on every SA and SP** in a stock racoon2 config, so the forwarder must bind an SA to its policy by tunnel endpoints/selector (and SPI+dst on inbound), never by `reqid` alone.
2. **`natt_sport/dport` are populated (500) even when `natt_type` = none.** Ports are only meaningful with `natt_type != NONE` (now documented in `proto.h`).
3. **AEAD key blob = cipher key || 4-byte salt** (`enclen=20` for AES-128-GCM): confirmed against iked, matching what `librte_ipsec` wants.
4. **spmd always uses `spdupdate` (upsert) and calls `SP_DUMP` at startup**; SP_ADD must be idempotent and SP_DUMP must be cheap. ~16 UDP bypass SPs per stack (IKE ports) accompany 3 tunnel SPs (in/out/fwd) — the datapath must honor the IKE bypass or route IKE via the exception path.
5. **racoon's `RCT_*` enum numbers are unstable across versions** (upstream inserted `RCT_ALG_AES_GMAC` mid-enum while this work was underway). Translating by symbol to IANA IDs in the shim was the right call; unmapped algorithms (GMAC, DES, IPComp) are refused, not guessed.
6. **XFRM-native fields**: `mark`/`if_id` selectors are refused (`EOPNOTSUPP`) rather than silently widening a policy; `offload_*` hints are ignored. M4 inline crypto needs a protocol extension to carry `offload_ifname`.
7. **Upstream moves fast** (136 commits between my first clone and the final one). The patch is pinned to `2fd758a`; `./build.sh e2e` is the rebase check. Upstream `make install` (out-of-tree) currently fails late on a missing `01setkey` hook; unrelated to r2dp, worked around in `build-racoon2.sh`.

## M1 — Forwarder MVP (1 port, 1 worker)  ✅ DONE
External DPDK forwarder with a working control plane **and** a real ESP data
plane. Exit gate MET (2026-10-25). **Final state:**
- **Control plane** (`fwd/ctl.c`, `fwd/dp.h` vtable): HELLO/caps, GETSPI
  (forwarder-allocated SPI), SA ADD/UPDATE/DEL/GET/DUMP, SP ADD/DEL/GET/DUMP,
  keys withheld, idempotent SP_ADD, cheap SP_DUMP, lifetime EXPIRE.
  `tools/r2dpctl dump|dump-sp|count` reads the live SAD/SPD over the wire.
- **Data plane** (`fwd/dp_dpdk.c`, DPDK ≥ 23.11): two-tap bump-in-the-wire
  (outer ESP tap, inner plaintext tap); `rte_ipsec_sad` (SPI+DIP) + AES-GCM
  `crypto_openssl0`; inbound decrypt (INGRESS direction, aad=8 per RFC 4106);
  egress encrypt via in-DP SPD with per-peer next-hop L2 learning and outer
  IPv4 checksum; NAT-T (RFC 3948, SAD-probed demux, both legs); byte + time
  lifetime EXPIRE (soft 1 / hard 2, hard withdraws SA); `gcm_kat` KAT.
- **M1 exit gate — MET (2026-10-25)**, reproduced live on Fedora 24.11.4:
  - **kernel-XFRM initiator ↔ r2dp responder**: `ping 192.0.2.1` 4/4, 0% loss.
  - **r2dp initiator ↔ kernel-XFRM responder**: `ping 192.0.2.2` 3/3, 0% loss.
    iked negotiates via the TAP; the forwarder decrypts and re-encrypts the
    flow (SAD is the source of truth).
  - **`r2dpctl dump` matches SAD**: `tests/sad_dump` (in-suite, no mock) installs
    SAs then asserts the wire dump returns exactly those (spi/proto/dst) —
    the reproducible exit-gate check.
  - Inbound decrypt + egress encrypt each verified live; deterministic
    two-tap round-trip proven (rtdo.py).
- **Tests**: meson 9/9 in both control and DPDK suites (`test_proto`,
  `test_mock`, `shim_contract`, `smoke_fwd`, `sad_dump`, `gcm_kat`, `dp_sa`,
  `ctl_poll`, `nh_test`).
- **Deps**: DPDK ≥ 23.11 LTS (libdpdk), libnuma, python3-pyelftools,
  hugepages or `--no-huge`.

### M1 data-plane notes (final state)
The hardest ground-truth bugs in the decrypt path (SAD byte-order, crypto
direction, AEAD iv.offset) and the egress path (unicast next-hop L2 vs
broadcast, newest-SA selection, outer checksum) are fixed and covered by
tests. Review findings H1–H5, M2 build-then-swap, M3 alignment, M5 parse/trim,
L7 getspi span, keyed in-place UPDATE, NAT-T, and lifetime EXPIRE are all
fixed and verified.

### Deferred (explicitly NOT M1, tracked)
- SPD deliberately linear (`rte_acl` → M3); D5 SPD priority-order + port
  selectors + IPv6; M9 egress/EVP/replay; L4 wsize; IPv6 datapath (SAD keys /
  selectors / framing — a separate milestone item).

## M2 — Lifecycle & protocol coverage
- **Builds**: lifetime tick + EXPIRE, hard-expiry RCU swap, ESN + replay window, AES-CBC + HMAC-SHA2, IPv6, NAT-T (UDP/4500 demux, non-ESP marker), HELLO capability bitmaps driving `rcpfk_supported_*`.
- **Deps**: none new (crypto_openssl / crypto_aesni_* vdevs).
- **Exit gate**: soft expiry triggers iked rekey with no packet loss in a ping flood; `samples/linux-matrix` rows (incl. NAT-T, ESN) pass against the forwarder; kernel-XFRM oracle matches on all algs.

## M3 — Multicore & update safety
- **Builds**: RSS multi-queue workers, per-lcore counters, rte_rcu_qsbr table swaps, SA-pinned ordering notes (one SA = one core), hugepage/NUMA setup docs.
- **Deps**: multi-queue-capable PMD (or net_tap multi-queue for CI), perf tools (optional).
- **Precondition (today's code)**: `r2dp-fwd` runs exactly one worker (`DP_NB_WORKERS == 1`, a `_Static_assert` in `fwd/dp_dpdk.c`; `dpd_start` refuses a second start and leaves extra lcores idle). The anti-replay window, SA byte counters, drop counters and the stuck-cryptodev quarantine are single-writer worker state with no locks or atomics. M3 must pin each inbound SA to one core (RSS/steering by SPI) or add a per-SA lock before raising it.
- **Exit gate**: N-tunnel scale test linear to core count; table churn (SA/SP add/del at 1k/s) under traffic with zero drops/crashes (ASan/TSan builds clean).

## M4 — Offload, on-demand, MTU
- **Builds**: `rte_security` inline crypto path, ACQUIRE for on-demand SAs, fragmentation + PMTU/ICMP, resync-on-reconnect snapshot hardening.
- **Deps**: inline-crypto NIC (hardware; optional, gated behind caps).
- **Exit gate**: forwarder restart mid-session resyncs without iked restart; PMTU black-hole test passes; inline path matches CPU path byte-for-byte.

## Multi-backend strategy (r2dp forwarders)

r2dp is a **control-plane protocol** (`proto.h`: SAD/SPD CRUD over a unix
SOCK_SEQPACKET socket); it is not a datapath API. A "backend" is therefore a
*forwarder implementation* that owns a packet engine and speaks the same r2dp
southbound. racoon2, `libr2dp`, and the shim are shared and unchanged across
backends; the `HELLO`/`HELLO_ACK` `features` + `enc_caps[8]`/`integ_caps[8]`
bitmaps (queried via `rcpfk_supported_enc/auth` / `r2dp_cap`) already let
each engine advertise what it can do and let racoon2 refuse the rest. That
handshake is the multi-backend seam — never fork the wire protocol per
backend.

**Target backend sequence** (each is a separate forwarder behind the same
r2dp contract; earlier milestones are the baseline, not a fork):

1. **DPDK** — M1–M4 as scoped. Userspace poll-mode, `librte_ipsec`, no special
   hardware, CI-testable. The always-available software baseline.
2. **P4-DPDK** — P4 datapath compiled onto DPDK (`p4c`/PNA backend). Same
   protocol, software-testable in CI, but the *same* `.p4` can later target a
   switch ASIC (Tofino-class) or SmartNIC. Gives the write-once →
   silicon-upgrade path; P4's portability only pays once the P4 abstraction is
   kept, so it is **not** parallel work in M1.
3. **XDP2** — [xdp2-dev/xdp2](https://github.com/xdp2-dev/xdp2) (rc3) is a
   **programming model / compiler**, not a competing engine: define a parse
   graph once and it emits an XDP/eBPF program *and* a standalone
   userspace/DPDK app. That matches the "external forwarder that can also run
   in-kernel" story and avoids hand-maintaining two datapaths. Young (rc3,
   some BPF-stack test skips), so treat as a *spike*, not the near-term bet.

**Protocol invariants every backend must honor** (from the M0 run, above):
- Forwarder is the SAD source of truth: `GETSPI` allocates; `SA_ADD`/`SP_ADD`
  must be idempotent; `SP_DUMP` is called at spmd startup and must be cheap.
- Bind SA ↔ policy by tunnel endpoints/selector + (SPI+dst inbound); never by
  `reqid` alone (finding 1).
- AEAD key blob = cipher key ‖ salt, matching `librte_ipsec` and XFRM
  (finding 3).  The salt is 4 bytes for GCM (RFC 4106, `enclen=20` for
  AES-128-GCM) and ChaCha20-Poly1305 (RFC 7634, `enclen=36`), but **3 bytes
  for CCM** (RFC 4309: `enclen=19` for AES-128-CCM).
  A 4-byte-salt CCM blob is silently a different key, so backends must
  size the salt per transform, not assume 4.
- Datapath must honor the ~16 UDP IKE bypass SPs or route IKE via the
  exception path (finding 4).
- Unknown transforms / XFRM-native `mark`/`if_id` are refused (`EOPNOTSUPP`),
  not silently widened (findings 5, 6).

Keeping these in every backend is what prevents "multi-backend" from decaying
into per-backend protocol forks.


### M1 interop build notes (retained from lab work)
- racoon2 built `--with-km-backend=r2dp --with-r2dp=PREFIX` (autoreconf +
  configure detects libr2dp via pkg-config `r2dp.pc`).

## Review follow-up (2026-10-25): protocol v2 and data-plane hardening
- **Protocol v2** (`R2DP_VERSION 2`): `r2dp_sa.pad0` becomes `dir`
  (`R2DP_DIR_IN`/`OUT`, 0 = infer for compatibility in the forwarder); the
  racoon2 shim sets it explicitly (GETSPI/UPDATE = IN, ADD = OUT).
  `wsize = 0` means "forwarder default (64)", never "anti-replay off".
- **Concurrency (M4)**: policies are published as pointers (release) and
  retired through QSBR before free; SA slots are published with a
  release-store of `used`; the control thread waits with
  `RTE_QSBR_THRID_INVALID` (passing the worker id skipped the grace period —
  a use-after-free caught by `dp_sa`'s concurrent-reader test).  Byte
  counters are atomic.
- **Policy semantics (M5)**: selectors match protocol and ports (first
  fragment only); most-specific policy wins; inbound decrypted packets must
  match an IN/FWD PROTECT policy bound to the SA's own tunnel endpoints and
  reqid — default deny.
- **Control server (M8 + minors)**: clients are non-blocking and a client
  that cannot take a reply is dropped instead of stalling the loop; reserved
  SPIs (< 256) and prefixes > 32/128 refused; lifetime clock starts at larval
  promotion; failed SP upsert restores the old policy; lifetime-only UPDATE
  does not touch the data plane; request buffers are scrubbed.
- **libr2dp**: tail-length checks for every message type, `MSG_NOSIGNAL`,
  send buffers scrubbed, HELLO validates seq/status and skips async messages.
- **Next hops**: the 64-entry MAC table evicts least-recently-seen entries.
- **CI**: `dp_path` runs outbound encrypt → inbound decrypt through the
  production code in the DPDK lanes.
- **Benchmark gate**: `bench/fwd_bench` measures `esp_outbound`/`esp_inbound`
  cycles/pkt (64B, 32-packet bursts) at 1, 65 and 201 tunnels; CI's DPDK
  lane runs it via `meson test --benchmark` and fails if the 201-tunnel cost
  exceeds 1.5x the 1-tunnel cost or 8000 cycles/pkt
  (`R2DP_BENCH_MAX_SCALE`, `R2DP_BENCH_MAX_CYC`).

## Backends: kernel XFRM vs DPDK

Both implement the same `fwd_dp` ops behind `r2dp-fwd --dp {dpdk,kernel}`
and pass the same scapy e2e suite (`tests/e2e/fwd_e2e.sh`, `BACKEND=`).

| | DPDK (`fwd/dp_dpdk.c`) | kernel (`fwd/dp_xfrm.c`) |
|---|---|---|
| Datapath | userspace poll-mode, `rte_ipsec` lookaside, `crypto_openssl` | Linux XFRM via NETLINK_XFRM |
| Transforms | AES-GCM-16 only (others `EOPNOTSUPP`) | GCM, CCM (3-byte salt), ChaCha20-Poly1305, CBC/CTR + HMAC |
| SPD | `rte_acl` + per-SA inbound index, QSBR-retired snapshots | kernel SPD, priority from `r2dp_sel_score` |
| Anti-replay | own 256-bit ESN window (DPDK's drops bits 32-63 per bucket) | ESN bitmap (`XFRMA_REPLAY_ESN_VAL`), window 64 if 0 |
| Drop accounting | per-reason counters (`SIGUSR1` dump) | kernel `XfrmIn*`/`XfrmOut*` MIB |
| Needs | hugepages or `--no-huge`, a NIC/tap, a core per worker | `CAP_NET_ADMIN` (netns ok), `xfrm_user` module |
| Use when | throughput, dedicated cores, CI without root | small sites, no spare cores, widest transform set |

The kernel backend is the oracle for transform interop; the DPDK backend is
the performance path.  `--dp-cleanup` removes the kernel backend's SAs/SPs
on exit.

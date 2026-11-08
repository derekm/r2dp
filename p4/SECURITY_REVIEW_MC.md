# Security Review: r2dp P4/SWX Multicore Data Plane

This is a **repeatable** review procedure for the multicore (`R2DP_P4_WORKERS=N`)
P4/SWX code surface in `fwd/dp_p4.c`. Run it again after any change to the
multicore path. Two prior single-instance reviews (`deleg_35f42512`,
`deleg_8988ae92`, `deleg_4387a8d3`, `deleg_25f498b8`) established the
load-bearing invariants below. Multicore must extend them, never weaken them.

The single-instance layout (`N=1`, `R2DP_P4_WORKERS` unset) is the security
baseline: it must remain **byte-identical in behavior** to the pre-refactor
binary. Any change that alters `N=1` behavior is a regression, not an
enhancement.

---

## 0. How to use this file

1. Build both lab targets and run the N=1 regression gate first (Section 9).
2. Walk Sections 1-8 against the **new** code surface (the shard-array,
   per-instance build/start, fan-out control plane, hash distributor,
   N-worker bench). Mark each as VERIFIED / NOT VERIFIED / FAIL with
   file:line evidence.
3. Run the multicore proofs on `.179` and `.165`.
4. Verdict: APPROVE / CHANGES REQUESTED, with the specific failing item.

A claim "N>1 works" is worth nothing if `N=1` moved or if any invariant
below is violated. Prefer running real code over reading intent.

---

## 1. Base invariants (must survive N-fold replication)

These were established for the single pipeline. Every one must hold on
**every shard**.

- [ ] **Unbound OUT PROTECT is fail-closed.** An OUT PROTECT policy with no
  bound egress SA (installed before its SA, or after a del) must resolve to
  `spd_discard`, never to a plaintext leak or to a match on a different SA.
  - Evidence: `sp-add ... action=protect` with no `sa-add`; `dump-sp` shows
    the policy; traffic must NOT appear on the wire clear (`a6`/`a7`
    action counters, not a sniff).
- [ ] **Plaintext leak audit:** `10/8 -> next_hop 1` (inner leg) must be
  programmed on every shard at start, and decrypt egress for a `10/8`-dst
  frame must egress inner, never outer. A failed `routing_table_0` add must
  fail the start (fail-closed), on every shard.
- [ ] **`meta.bypass = 1` in the inbound non-ESP else is forbidden.** The SAD
  memcpy and the Limit-3 drop must live in the extern; a bypass frame must
  not change the SAD gate.
- [ ] **Header/text consistency:** any comment describing table keys, offsets,
  priorities or the SPD key image must match the code (see the historical
  `[4][5]` / `[0][3][7]` delete bug and the `@15` vs `@16` length offset).
  "Fix the code to match the comment" is how headers break.

## 2. Control-plane mirror (shared) vs per-shard tables

The SAD/SPD *mirror* (`pr->sad[]`, `pr->spd[]`) is control-plane truth and may
be shared. The SWX *tables* (`inbound_table_0`, `outbound_table_0`,
`next_hop_table_0`, `routing_table_0`) and the ipsec extern's crypto SA set
are **per shard** and must be programmed identically on every shard.

- [ ] **Fan-out is all-or-nothing.** If `sa_add`/`sp_add`/`sp_del` programs
  shard 0 then fails on shard k, the operation must roll back on ALL shards
  AND the shared mirror must reflect the failure (ctl keeps its copy on
  error). A half-programmed plane (some shards have it, mirror says no) is a
  fail-open/state-divergence defect. How is the commit made atomic across
  shards (single `commit`, or per-shard with full rollback)?
- [ ] **Per-shard SA identity.** The crypto SA id is per-extern (each shard's
  `rte_swx_ipsec` returns its own id). The mirror/policy must track
  per-shard `sl_id`, and each shard's table rows must reference **that
  shard's** id — not shard 0's. A row in shard k pointing at shard 0's id is
  a cross-shard dangling reference.
- [ ] **Delete proof per shard.** `sp-del` of a `/32` must remove that row on
  *every* shard, and re-inject must move `a6`(PROTECT)`->a7`(BYPASS) on every
  shard. `dump-sp` (mirror) must agree. A delete that only hits shard 0
  leaves other shards applying stale policy.
- [ ] **Rebind on sa_del / rekey.** `p4_spd_rebind` after an outbound SA
  delete/rekey must run on every shard, and on failure restore the
  pre-rekey SA on every shard (no shard left referencing a deleted crypto SA).
- [ ] **`-E2BIG` before its slot is still enforced per shard** — an OUT
  policy the ACL cannot name (port/scope/host-bit split) must be refused,
  not aliased, on the control path regardless of N.

## 3. Cryptodev / ipsec extern

- [ ] **One cryptodev, N queue pairs.** `p4_crypto_init` must configure the
  device with `nb_queue_pairs = N` (created with
  `max_nb_queue_pairs=N` on the EAL `--vdev`), and each shard's extern must
  be created with a distinct `crypto_dev_queue_pair_id` (0..N-1). Two
  shards on the same queue pair serialize (perf) or, worse, misroute crypto
  completions.
- [ ] **QP bounds check.** `crypto_dev_queue_pair_id >= max_nb_queue_pairs`
  must be refused (the extern itself enforces this; do not let it fail after
  partial setup). A DPDK build with default 8 QPs and `R2DP_P4_WORKERS>8`
  must fail closed, not over-subscribe.
- [ ] **No device / `-ENODEV`** still tolerated (control-only, ESP dropped,
  IKE flows), on every shard, only when there is truly no device.

## 4. Per-shard isolation (no cross-core shared mutable state)

- [ ] Each shard owns its **own rings** (`R2DP_IN0_<i>` etc., unique names),
  its **own pipeline object**, its **own extern**. No two worker threads
  call `rte_swx_pipeline_run`/`rte_swx_ipsec_run` on the same object
  (`rte_swx_*` is single-owner).
- [ ] Ring-name collision check: the iospec / `p4_ring` must emit
  per-shard-suffixed names; `rte_ring_lookup` must not return a shared ring.
  Two shards enqueuing to the same `IP_IN` ring is a cross-core data race.
- [ ] The shared `pool` may be a common mempool (it is thread-safe), but no
  *packet metadata* / table / extern state may be shared between workers.

## 5. Steering (live path)

- [ ] Inbound/outbound RX is steered to a shard by a **deterministic hash on
  the flow**; all packets of one flow/SA land on the same shard (per-SA
  affinity). Round-robin or load-dependent assignment breaks SPI replay
  state and is a correctness defect, not a perf choice.
- [ ] The hash is stable across relaunch (fixed seed where the NIC's RSS
  would be fixed). A flow's shard must not change on restart.
- [ ] **Bench path is exempt from steering** only because each bench shard
  self-injects its own independent flow; the live path must still steer.

## 6. Worker / threads

- [ ] Each shard runs its own worker pinned to its own lcore (`pthred_setaffinity`
  or EAL `remote_launch` to a distinct lcore). No two workers share a core.
- [ ] `running` flag is per-shard `atomic_int`; stop joins every worker, frees
  every pipeline/extern/rings on every shard — no leak on a partial start.
- [ ] Stats (`SIGUSR1`) aggregate across shards honestly (sum the
  per-shard RX/TX/esp), or label per-shard. Do not report shard 0's numbers
  as the whole.

## 7. Bench (tap-free)

- [ ] `R2DP_P4_BENCH=1` + `R2DP_P4_WORKERS=N`: N bench workers run, one per
  shard, each self-injecting and counting its own `pkt/cyc/pps`; the reported
  figure is the **sum**, honestly labeled.
- [ ] N=1 bench reproduces the pre-refactor single-instance number
  (`.165` ~0.99-1.00 Mpps openssl 64B; `.179` aesni 1.71-1.72 Mpps @ 64B).
  Any change here is a regression.
- [ ] Frame size (`R2DP_P4_BENCH_SIZE`) and IPv4 total-len/UDP len fields are
  consistent per size on all shards (see historical `@15` comment bug).

## 8. Resource / rollback hygiene

- [ ] On a failed multi-shard start, every already-created shard's
  pipeline/extern/rings/cryptodev QP are freed (no orphaned pools).
- [ ] `free(d->pool)`/`rte_mempool_free` on refused start paths (the
  historical orphaned-16384-mbuf-pool defect).
- [ ] No `pkill`/`killall` by name in any test harness fallback (multiple
  concurrent tests).

## 9. Runbook: verify by running

**Build (both targets):**
```
# .165 (4-core): openssl only, dp_max_wk=8
meson setup build -Ddp_max_wk=8 -Denable_p4=enabled
ninja -C build fwd/r2dp-fwd r2dpctl bench/fwd_bench

# .179 (12-core, AES-NI): link against source DPDK for ipsec_mb
PKG_CONFIG_PATH=/home/yescorp/dpdk-src/build/meson-uninstalled:/home/yescorp/dpdk-src/build/meson-private \
  meson setup /home/yescorp/p4bm2 /home/yescorp/r2p4src -Ddp_max_wk=12 -Denable_p4=enabled
ninja -C /home/yescorp/p4bm2 fwd/r2dp-fwd r2dpctl bench/fwd_bench
```

**N=1 regression gate (must pass before any N>1 claim):**
```
# .165 openssl 64B  -> expect ~0.99-1.00 Mpps / ~2505 cyc
R2DP_P4_BENCH=1 r2dp-fwd --dp p4 ... --vdev=crypto_openssl0
# .179 aesni 64B    -> expect ~1.71-1.72 Mpps / ~1851 cyc
R2DP_P4_BENCH=1 r2dp-fwd --dp p4 ... --vdev=crypto_aesni_mb0
```

**Multicore (`.179`, aesni):**
```
R2DP_P4_WORKERS=4 R2DP_P4_BENCH=1 r2dp-fwd --dp p4 ... \
  --vdev='crypto_aesni_mb0,max_nb_queue_pairs=4' --no-huge -m 1024
# install SA+SP; expect 4 bench workers; aggregate ~= 4 x per-shard
```
**Proven 2026-11-08 (this refactor), aggregate tap-free Mpps (sum of
per-slice best_cyc_pkt pps):**
- `.179` aesni 64B: W1 **1.728**, W2 **3.240**, W4 **4.855**, W6 **5.781**,
  W8 **6.605**.
- `.165` openssl 64B: W1 **0.998**, W2 **1.884**, W3 **2.613**, W4 **3.344**.
- N=1 restates the historical single-instance figure (1.72 / 0.99) => the
  regression gate is intact at the same commit that runs N>1.
- Fan-out proven on the log: every shard prints `slice i ipsec SA add ok`
  and `slice i OUT BIND installed` with the same selector; each shard's
  extern gets its own sa_id.

**Status at this commit (`d23eb26`):**
- VERIFIED (bench path): N=1 regression, per-shard build/start/fan-out,
  one cryptodev N QPs, per-shard pipeline/extern/pool/rings, core pinning,
  N-worker bench, honest aggregate, no pool OOM under `-m 1024`.
- **VERIFIED (live path):** Section 5 RX steering implemented + live-proven.
  A single `p4_rx_worker` distributor hashes each frame to a slice (ESP ->
  outer dst+SPI for per-SA replay affinity; else 5-tuple), one RX thread =
  single ethdev consumer.  Live-proven on `.165` N=2 (openssl, root tap):
  both shards `SA add ok` + `OUT BIND installed`; `crypto enq=deq>0` (real
  ESP); `a6(PROTECT)>0` out0 egress on the forwarding shard.
- **VERIFIED delete-proof-per-shard (live, N=2).** After `sp-del` +
  re-inject: before `a6=24467 a7=0`; after `a6=24467 a7=15192 ob_miss=15192`
  -- the outbound row was removed on every shard and new frames fall to the
  bypass default, matching the shared mirror.  `p4_live_proof.sh` runs this.
- **VERIFIED hash stability across relaunch.** `p4_flow_slice` is a pure
  function (fixed xor-fold seed, no state/env), so same (flow, N) => same
  slice on every launch; checked deterministically for representative ESP +
  5-tuple flows across N=1..8.
- **VERIFIED (independent review, `deleg_c61620f6`) fixes in `7ff16bc`:**
  - outbound `SA_DEL` no longer falls through into the inbound cleanup
    (previously deleted SA id 0 on every slice); the `return` is restored.
  - fan-out is all-or-nothing on the schedule phase: `spd_bind` / `sp_del`
    abort EVERY shard on the first schedule failure (no pending delete
    left to commit later = no delayed bypass drop); `sp_add` already did.
  - `R2DP_P4_WORKERS > R2DP_P4_MAX_INST (8)` now REFUSES (-EINVAL) rather
    than silently clamping, so the plane is never under-provisioned vs.
    what the operator asked for.
- Remaining for a full APPROVE (procedures, not missing code):
  - live replay/seq-integrity assertion (same-flow monotonic seq on the
    pinned shard) -- steering makes this possible by construction (per-SA
    affinity) but an explicit multi-packet replay test is still a reviewer
    action.
  - The bench W=1 "restates the historical figure" claim is a **bench**
    gate; the live-path N=1 delete/affinity behavior was re-proven in
    review (two outbound SAs, delete id 1 keeps id 0) but should be run
    again after the 7ff16bc fixes.

**Checks on the live path (memif/tap), not just bench:**
- per-SA affinity: `p4_live_proof.sh` proves a flow steers to one shard
  (N=2, one-flow case) with crypto enq/deq on that extern.
- delete proof per shard: proven live (a6->a7 on every shard) above.
- replay/seq integrity: steering pins the flow to one shard by (dst,spi)
  so replay state is single-owner; an explicit multi-packet replay test is
  the remaining reviewer assertion.

---

## 10. Sign-off

| # | Invariant | VERIFIED? | File:line | Notes |
|---|---|---|---|---|
| 1 | N=1 byte-identical |  |  |  |
| ... | (one row per checkbox) |  |  |  |

Verdict: **APPROVE / CHANGES REQUESTED** — summary of the failures.

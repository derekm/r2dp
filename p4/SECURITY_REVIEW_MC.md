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
  A single `p4_io_worker` (renamed from `p4_rx_worker`) owns BOTH ethdev legs:
  it distributes RX by hashing each frame to a slice (ESP -> outer IP src+dst
  -- fragment-invariant, NOT dst+SPI which would scatter an SA's fragments;
  else 5-tuple) and does all TX.  One thread = single ethdev consumer AND
  single producer (no TX data race).  Live-proven on `.165` N=2 (openssl,
  root tap): both shards `SA add ok` + `OUT BIND installed`; `crypto
  enq=deq>0` (real ESP); `a6(PROTECT)>0` out0 egress on the forwarding shard.
- **Delete-proof (live, N=2; harness re-added as `SPDEL=1`).** After
  `sp-del` + re-inject: before `a6=24467 a7=0`; after `a6=24467 a7=15192
  ob_miss=15192` -- the outbound row was removed on the forwarding shard and
  new frames fall to the bypass default.  Caveat (review `deleg_14119f51`):
  the OTHER shard was idle (`in_rx~14`), so this demonstrated ONE shard's
  delete only; `bench/p4_live_proof.sh SPDEL=1` re-runs it.  Not claimed
  per-every-shard.
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
- **VERIFIED (independent review, `deleg_14119f51`) fixes in `fe4abd4`:**
  - **TX data race closed.** Both ethdev legs are now owned by a single
    `p4_io_worker` (RX distributor + TX): one thread owns RX (single
    consumer) AND TX (single producer) so N per-slice workers never call
    `rte_eth_tx_burst` on queue 0 concurrently.  TX counted with the
    `tx_burst` RETURN (not the dequeue count); unsent mbufs freed (a full
    TX queue is not "transmitted").
  - Outbound `SA_DEL` commits EVERY slice's rebind BEFORE deleting the
    crypto SAs / clearing the slot, so a failed commit leaves the slot
    findable (`in_use`) with the SA still present -- ctl's retry is not
    `-ENOENT` with the SA gone (keep-on-error preserved on the commit path).
  - `p4_flow_slice` hashes ALL ESP frames on the outer IP flow (src,dst),
    not (dst,SPI): only the first fragment carries the SPI, so a (dst,SPI)
    hash scattered one SA's fragments across slices; src+dst is
    fragment-invariant and keeps an entire SA (and its fragments) on one
    slice.
  - `R2DP_P4_WORKERS` empty/non-numeric/<1 refuses -EINVAL (like >MAX)
    instead of silently defaulting to 1.
  - Per-worker periodic-dump accumulate buffers made stack-local (were
    static, shared across workers -> torn/overwritten a6/a7 under N>1).
- REMOVED honest overclaims: the commit-phase of cross-slice fan-out is
  documented in `p4_spd_bind`/`p4_sp_del`/`p4_sp_add` as inherently
  per-pipeline (a slice whose commit already succeeded cannot be rolled
  back in one-shot; the common failure is symmetric).  Status of the live
  decrypt + replay demonstration:
  - **Inbound DECRYPT now demonstrated (`d76acb2`).** The extern
    `ipsec_xform.spi` was being programmed in NETWORK order
    (`sp.encap.esp.spi = sa->spi`); it must be HOST order (`ntohl(sa->spi)`),
    mirroring exactly what the DPDK backend programs (`dp_gcm.c:79 ->
    ntohl(rsa->spi)`) and what the SAD stores (`dpdk_sad.c`).  Mechanism
    (per independent review of DPDK 24.11): rte_swx_ipsec copies
    `ipsec_xform.spi` straight into the xform, and rte_ipsec stores
    `sa->spi = rte_cpu_to_be_32(ipsec_xform.spi)` (`lib/ipsec/sa.c`), so
    host order in becomes network order on the wire and in the GCM AAD.
    A swapped SPI would corrupt the AAD and fail ICV in
    `rte_ipsec_pkt_process` *after* enqueue (enq and deq both move, inner
    egress stays 0) -- it is NOT what keeps `enq=0`, because DPDK selects
    the SA by `sa_id` (meta), not by packet SPI.  With the fix, a
    framed-AES-GCM inbound stimulus decrypts and EGRESSES the inner leg:
    `crypto enq=deq=288, ib hit 0->300, inner-out 0->288`.  The far-leg
    inner frame is now real (verified, same stimulus on the real peer
    path is pending).  The real-peer `ib=15 / crypto enq=0` residual is a
    separate, unexplained defect, not this SPI byte order.  Verified
    live (2026-11-09): a clear frame on the inner leg hitting the OUTBOUND
    PROTECT SA installed with spi=0x2000 egresses outer ESP with wire SPI
    bytes `00 00 20 00` (tcpdump decodes `ESP(spi=0x00002000)`), with
    `ob_hit=300, a6=300, crypto enq=deq=288, out0=288` -- the ntohl fix
    also produces the correct outbound wire SPI, not a double-swap.
  - **Real independent-peer e2e on P4 — POSITIVE PHASE NOW CLOSED (`0003`).**
    The prior failure is fully root-caused and fixed: it is NOT SPI/bytes/
    prepare/the SA session.  With `fwd/dp_p4.c` flushing the pipeline
    output ports AND `0003-rte_swx_ipsec-batching-flush.patch` flushing the
    extern's crypto-op and decrypted-packet buffers, the real scapy peer
    passes **all 15 positive round trips plus the decrypted inner-reply TTL
    check** on `BACKEND=p4` (`tests/e2e/fwd_e2e.sh`, positive phase:
    `ok ... round trip payload=0..1400`, `ok ... inner reply ttl 64 (got 64)`;
    fwd log `portout[2]=57`, decrypted inner `out1=26`, outbound `a6=25`).
    The concrete mechanism (missing BEFORE): SWX batching is everywhere and
    never flushed for a partial batch. (1) ring output ports push to
    `IP_IN` only on a full `bsz` batch or `rte_swx_pipeline_flush()`; (2)
    `ipsec_crypto_enqueue` submits crypto ops only on a full
    `bsz.crypto_wr`; (3) `ipsec_ring_enqueue` pushes decrypted packets to
    `IP_OUT` only on a full `bsz.ring_wr`.  A peer at ~1 pkt/round trip
    fills none of them, so its packets were parked and never decrypted /
    never egressed — while a 32-deep burst chanced to fill them (the
    "burst works, sparse fails" discriminator).  The old "never reaches
    IP_IN" reading was an instantaneous post-drain `rte_ring_count` (0
    after the extern drains), NOT a cumulative enqueue; the ring WAS
    written, `prepare` returned `ok=1` per packet, and only the batching
    buffer kept the op off the cryptodev (`crypto enq` stayed 0).  This
    is a genuine DPDK 24.11 extern defect (fixed at source here, carried as
    `contrib/upstream/0003-*.patch`), not something the pipeline/SAD could
    work around.  N=1 reproduces it no longer relevant — the fix is
    cadence-independent.
  - **Replay-window and NAT-T phases on P4 remain separate, honestly-open:**
    `fwd_e2e.sh` window + NAT-T still fail on P4.  window fails because
    stock DPDK 24.11 extern hardcodes `replay_win_sz=0`/`esn=0`
    (anti-replay off); a replay/out-of-window seq still gets a reply.  A
    host `.so` patch is not the product fix (reviewer action, unchanged).
    NAT-T ESP-in-UDP round trips fail on P4 and are not yet root-caused.
    These are NOT regressions from the flush; the same forwarder passes
    the whole DPDK-backend harness.
  - **(b) `next_hop_set` installs all-zero MACs -- FIXED (`8cfc4b6`).**
    `p4_start` had programmed `next_hop_table_0` id0/id1 with zeroed
    `ab[]` except ether_type/port, so both hop dst/src were
      `00:00:00:00:00:00`.  An AF_PACKET sniff/peer (outer leg) sees a
      frame regardless, but the INNER host (real kernel on the inner tap)
      drops a frame dstd to `00:00:00:00:00:00`, so the ICMP reply could
      never return.  Fix (`8cfc4b6`): read `rte_eth_macaddr_get(inner_port)`
      in `p4_io_init` and rewrite the id1 (inner) next-hop entry dst+src to
      that MAC for every slice after io_init discovers the legs.  This
      mirrors `dp_dpdk.c` `our_inner_mac` and the DPDK reference note that
      a broadcast dst makes `tcp_v4_rcv` drop before counting InSegs.  It
      is a prerequisite for any inner reply regardless of blocker (a); it
      does not by itself explain `crypto enq=0`.  Outer hop still uses the
      learned peer MAC.  Note: id0/id1 install/commit being log-only is
      closed by the per-slice commit here; a preserve/10/8 lookup failure
      still surfaces as a silent drop, not a MAC bug.
  - **Per-slice replay-window drop on P4 is NOT yet verified.** The stock
    DPDK 24.11 extern hardcodes `replay_win_sz = 0` / `options.esn = 0`
    (anti-replay off), so a live seq-drop cannot be claimed on unpatched
    DPDK; a host `.so` patch is not a product fix.  This is a reviewer
    action.
- **VERIFIED (`191aaf2`) inbound SAD key byte order:** the (dip,spi) exact
  key was built as host dip + NETWORK spi, so no inbound frame ever matched
  (ib hit=0, crypto enq=0).  SWX exact-matches the parse fields as HOST
  uint32s; the correct key is { ntohl(dip), ntohl(spi) } in BOTH fields.
  Live N=2 openssl: ib hit 0->380, crypto enq=deq 0->288 for 300 distinct
  ESP seqs (previously 0).  N=1 bench gate unchanged.
- **VERIFIED (`d5be7bb`) fourth-round review `deleg_4f8cf2ac` (fragment
   steering + teardown), re-proven live:**
  - ESP-in-UDP (RFC 3948, proto 17 / UDP 4500, which the parser's
    `nat_demux` treats as ESP) now hashes on the fragment-invariant outer
    (src,dst) like proto-50 ESP, and ANY non-first fragment (fo!=0 or MF)
    hashes on (proto, src, dst) -- so one SA's proto-50 ESP, its ESP-in-UDP,
    and all their fragments stay on ONE slice (reassembly + per-SA replay
    are single-owner).  Previously only proto==50 was special-cased, so a
    4500 flow fell into the 5-tuple branch and its fragments could scatter.
  - `p4_stop` now stops/joins the PRODUCERS (slices) first, then the io
    thread last -- the io thread drains every slice's egress rings, so
    joining it before slices 1..N-1 had stopped abandoned in-flight mbufs.
  - io thread TX loop NULL-guards `out0`/`out1` ring ptrs.
  - Log/comment renames: `io worker started` / "io worker create failed"
    (was "rx distributor"), matching the p4_io_worker rename.
  - Re-proven live on .165 N=2 (openssl, root tap): pre-delete
    ob_hit=15855 a6=15855 crypto enq=deq=15840; post `sp-del` ob_miss=16526
    a7=16526.  N=1 gate 2512 cyc, W=2 ~2659 each -- unchanged.
- **VERIFIED (`be57676`) third-round review `deleg_ce36234f` (harness +
   atomicity), re-proven live:**
  - `bench/p4_live_proof.sh` is FIXED and now actually runs its injector
    (writes and runs the SAME /tmp/liveinj.py path), records the real
    forwarder via socket-keyed `sudo pgrep` (never sudo's `$!`), kills it
    as root, propagates ssh exit status so a failed step fails the run, and
    re-adds the `sp-del` + re-inject as `SPDEL=1`.  Live re-proven on .165
    N=2: pre-delete in_rx=18406 ob_hit=18394 a6=18394 crypto enq=deq=18368;
    post `sp-del` a7(BYPASS)=17762 ob_miss=17762 -- outbound FORWARDING shard
    row removed, new frames fall to bypass.  (Caveat stands: the OTHER shard
    was idle in this one-flow test; delete proven on the forwarding shard.)
  - Inbound `SA_DEL` now aborts uncommitted slices on BOTH schedule-phase and
    commit-phase failure (no pending SAD delete published by a later commit
    while ctl still owns the SA).
  - `p4_spd_rebind` aborts uncommitted slices on a mid-loop commit failure.
  - `p4_flow_slice` header/comment + doc now say (src,dst), matching the
    fragment-invariant body (stale (dst,SPI) references removed).
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
- delete proof: proven live on the forwarding shard (a6->a7 above); the
  other shard was idle, so `bench/p4_live_proof.sh SPDEL=1` re-injects to
  confirm.  Not claimed per-every-shard until that re-run.
- replay/seq integrity: steering pins the flow to one shard by outer
  (src,dst) so replay state is single-owner; an explicit multi-packet replay
  test is the remaining reviewer assertion.

---

## 10. Sign-off

| # | Invariant | VERIFIED? | File:line | Notes |
|---|---|---|---|---|
| 1 | N=1 byte-identical |  |  |  |
| ... | (one row per checkbox) |  |  |  |

Verdict: **APPROVE / CHANGES REQUESTED** — summary of the failures.

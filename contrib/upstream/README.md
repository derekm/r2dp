# Upstream contribution drafts

Grounded drafts capturing the Limit 4 (SPD prefix/ANY) work for submission
to the DPDK and p4c projects. These are **not** yet submitted or merged; the
r2dp repo has no remote/credentials for those upstream orgs, so they are
packaged here for a human to route to the project lists. Everything stated
about SWX/ACL behaviour and the key layout was verified on-box against DPDK
`v24.11` (`rte_swx_table_wm.c`, `rte_swx_ctl.c`, `rte_swx_pipeline.c`) and
p4c `backends/dpdk` (ternary -> wildcard lowering in `spec.cpp`), and proven
by the Limit 4 implementation in `p4/r2dp.p4` + `fwd/dp_p4.c` (`a8aedd2`).

## Files

- `0001-dpdk-wildcard-runtime-programming.patch` — DPDK docs (`pipeline.rst`)
  + example note (`examples/pipeline/README.rst`): documents that SWX
  wildcard (ACL/ternary) tables are runtime-programmable via non-incremental
  rebuild, and the gap-aware, big-endian ACL key layout.
- `0002-p4c-spd-prefix-sample.patch` — p4c `backends/dpdk/examples/spd_prefix.p4`
  (a real prefix/ANY SPD, not the exact-only crypto demo) + a `README.md`
  wildcard-key-layout note.
- `0003-rte_swx_ipsec-batching-flush.patch` — DPDK `rte_swx_ipsec.c`: the
  SWX ipsec extern batches crypto ops to a full `bsz` before submitting and
  batches decrypted packets to a full ring before pushing to `IP_OUT`.  A
  sparse live peer (one packet per round trip) never fills either, so its
  packet sat parked in `in.cops[]`/`out.pkts[]` forever and was **never
  decrypted / never egressed** regardless of how correct the pipeline and
  SAD were.  This flushes both partial buffers at the end of every
  `rte_swx_ipsec_run`.  Same root cause as the pipeline output-port writer
  (flush in `fwd/dp_p4.c`): SWX batching is a throughput optimization, not
  a correctness gate, and the r2dp forwarder runs `pipeline_run` +
  `ipsec_run` on a live packet path where a single frame is the common case.
  Verified on `.165`: after this patch the real scapy peer passes all 15
  positive round trips on the P4 backend (previously `crypto enq=0` at peer
  cadence).
- `0004-rte_swx_ipsec-natt.patch` — DPDK `rte_swx_ipsec.c` + `rte_swx_ipsec.h`:
  RFC 3948 ESP-in-UDP (NAT-T) for the SWX ipsec extern.  0003 and 0004
  together are the full DPDK extern patch series (0004 applies on top of
  0003; both verified by `git apply --check` against pristine + the live P4
  harness).  NAT-T changes: (1) add `udp_encap` + `udp.sport/dport` to
  `rte_swx_ipsec_sa_params` and plumb them into `ipsec_xform_get`; (2) set
  the tunnel IPv4 outer `next_proto_id` to UDP (17) when `udp_encap` is set
  (was hardcoded ESP/50, so the UDP ports were misread as the ESP SPI on
  the wire); (3) inbound `pre_crypto` folds the 8-byte UDP wrapper out
  (memmove + `rte_pktmbuf_adj`, rewrite outer proto to ESP, shrink
  total_length) exactly like the DPDK backend `dpdk_esp.c`, since `esp_inb`
  locates ESP at l2+l3 and does not strip UDP itself; (4) `rte_swx_ipsec_sa_add`
  builds an inbound NAT-T SA with `udp_encap` cleared (so rte_ipsec does not
  also strip) while outbound keeps it (so rte_ipsec inserts the UDP/4500
  wrapper).  Verified on `.165` P4 backend: 3 NAT-T round trips, egress
  framing (UDP 4500->4500, SPI right after), keepalive, IKE and
  post-IKE health all pass; the DPDK backend passes the whole harness as a
  control.
- `0005-rte_ipsec-replay-window.patch` — DPDK `lib/ipsec/ipsec_sqn.h` +
  `lib/pipeline/rte_swx_ipsec.{h,c}`: real RFC 4303 anti-replay.  Two
  source bugs had left anti-replay silently off / broken:
  (1) `esn_inb_update_sqn` held the per-packet bit mask in a `uint32_t`
  and assigned `(uint64_t)1 << (sqn & 63)`, so for any bucket-local bit
  position >= 32 the mask truncated to 0 and the seen-bit was never
  written -- a replay or far-old sequence at a high sequence number was
  accepted (the replay window is `uint64_t rsn->window[]`, and the check
  path already uses `((uint64_t)1 << bit)`).  (2) `rte_swx_ipsec_sa_params`
  had no anti-replay field and `ipsec_xform_get` hardcoded
  `replay_win_sz = 0` (anti-replay permanently off); added
  `replay_win_sz` and plumb it into the xform so `fill_sa_replay` arms a
  sliding window (0 stays off).  The r2dp ctl SA's `wsize`/`replay_win`
  is carried as `replay_win_sz = r2dp_sa_window(sa) - 1` (rte_ipsec's
  window is inclusive at its top while r2dp's is strict, so -1 makes the
  dist-63-accepted / dist-64-rejected boundary agree with the DPDK
  backend).  Verified on `.165` P4 backend, full harness: replay of an
  accepted seq, far-old seq, and the dist-63/64 boundary all behave
  identically to DPDK (37/37 PASS).  Applies on top of `0004`.

## Submission route (upstream)

- **DPDK**: send to `dev@dpdk.org` via `git format-patch` / `git send-email`
  from a DPDK checkout, `--to dev@dpdk.org --cc stable@dpdk.org` (if
  backporting the doc to 24.11/25.11). Subject prefix `[PATCH]`.
- **p4c**: open a pull request on `p4lang/p4c` against `backends/dpdk`.
  The example should be exercised with `p4c-dpdk --arch pna
  examples/spd_prefix.p4 -o spd_prefix.out` before submission (the harness
  example boilerplate mirrors `examples/ipsec.p4`, which compiles).

## Third opportunity (not yet drafted): p4-dpdk-target DPDK-version staleness

`p4lang/p4-dpdk-target` pins DPDK **22.07-rc2** and carries a local patch
`007-Fix-pipeline-structs-initialization.patch` described as temporary.
Landing those struct-init fixes upstream in DPDK (and bumping the submodule
to a supported release) removes a whole class of "SWX behaviour differs from
latest DPDK" divergence. Draft and file there when bandwidth allows.

## The reproducible finding (for reviewers)

SWX wildcard tables are *not* "built once / immutable": `.add/.del == NULL`
only disables incremental updates. `rte_swx_ctl` applies entries
non-incrementally — on `commit`, `table_rollfwd0` duplicates
`entries + pending_add + pending_modify1` and calls `table->ops.create` to
rebuild the whole ACL (DPDK "support non-incremental table updates", 21.05,
Dumitrescu; present in v24.11 and main). `p4-dpdk-target`'s pipe_mgr drives
the same path for P4Runtime ternary/TCAM entries. The two real sharp edges
are: (1) the ACL key is gap-aware (header byte offsets, not packed), and
(2) masks/values are big-endian with the most-specific rule at the lowest
`key_priority`.

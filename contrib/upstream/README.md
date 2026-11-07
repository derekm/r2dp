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

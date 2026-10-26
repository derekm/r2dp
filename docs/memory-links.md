# Lineage ↔ Agent Memory Context Links

This document lives on the `lineage` branch and cross-references each commit
and branch in the lineage DAG to the agent's durable memory context — the
entries recorded in `AGENT_MEMORY_MILESTONES.md` on the `agent` branch.

Purpose: anyone (or any future agent session) walking this DAG can jump from
a commit/branch to the memory that explains *why* it exists, what was
learned building it, and what correction/compaction anchor it carries.

The memory ledger is authoritative; these links are pointers into it.

---

## Commit-level links (lineage DAG, oldest → newest)

| Commit | Subject | Relevant agent-memory milestone(s) |
|---|---|---|
| `5361910` | zip1: r2dp M0 base (upstream lineage root) | § [2026-10-24 — r2dp project landed (recognition)](/AGENT_MEMORY_MILESTONES.md#m0-recognition); the head of the "HEAD advanced past both zips" correction. Partial snapshot — no meson.build, no libr2dp/client.h. |
| `b57d97f` | zip2: r2dp M0+M1 package (direct upstream lineage child) | § [2026-10-25/26 — lineage DAG reconstruction](/AGENT_MEMORY_MILESTONES.md#lineage-dag); carries the complete shared control-plane engine (`libr2dp/cp.{c,h}`, `r2dp_cp_hooks`) — the "generic dataplane backends" design. |
| `d9f3de7` | ci: baseline lineage-DAG test suite (walk all DAG commits) | § [2026-10-26 — lineage-DAG CI baseline](/AGENT_MEMORY_MILESTONES.md#ci-baseline); § Windows /tmp-vs-native-git path pitfall. |

---

## Branch-level links

| Branch | Lineage context | Agent-memory context |
|---|---|---|
| `lineage` | The zip package history (M0 → M0+M1 → CI). Root commit `5361910` is an orphan (no git parents) by design. | § [lineage DAG reconstruction](/AGENT_MEMORY_MILESTONES.md#lineage-dag) — why an orphan root is correct: the zips and the git history are *divergent siblings*, not ancestors, so the lineage is re-expressed as a clean two-snapshot DAG rather than rebased. |
| `agent` | Carries the memory ledger itself (same surface as `lineage` + `AGENT_MEMORY_MILESTONES.md`). | § [2026-10-24 — r2dp-interop-harness skill (compaction anchor)](/AGENT_MEMORY_MILESTONES.md#interop-skill); § authorship-rewrite rule. |
| `mark-cleanroom` | Alternative clean-room lineage: M0 `650b26e` → M1 `7669f9a` → M1.5 `f249fda` (+ `kfwd` kernel-reference backend). Shares the same M0 root as `main`. | § [lineage DAG reconstruction](/AGENT_MEMORY_MILESTONES.md#lineage-dag) — the three-artifacts reconciliation (zip#1, zip#2, mark-cleanroom). |
| `main` | The divergent incremental implementation (85 commits) sharing M0 root `650b26e`. | § Corrections — "sibling not ancestor"; the tree diff is the ground truth, not commit-message intent. |

---

## How to use

- Walk the DAG: `git log --graph --oneline --decorate lineage`
- Read a commit's memory: find it in the commit table above, then read the
  linked milestone in `AGENT_MEMORY_MILESTONES.md` on the `agent` branch.
- The tabulator `meson test`/CI result for a given snapshot is produced by
  `tests/ci_dag.sh` (see its header) — each commit is built in isolation the
  way that snapshot can actually build.

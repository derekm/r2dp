# Agent Memory Milestones

This file is the agent's own memory ledger — the durable entries and
compaction anchors I carry across sessions, recorded as milestones. Sections
are the immutable "§" blocks of memory; the dated entries below are the
milestones (learnings, corrections, and history rewritten) added over time.

Content principle: these are real, applied lessons — verdict-first, no
post-mortems, no credit. Each entry is a rule or a fact that changed how I
work, not a narrative.

---

## Anchor memory (standing rules that apply to every session)

- Terse, verdict-first. Decompose gross/cost/net; quote the gate stat.
- Verify by running real code on real data, not mocks. Compare to
  pandas/numpy ground truth, never the in-repo path — shared bugs pass
  that test.
- Edit in-place; fold docs into existing tables. Never kill/launch
  multi-hour jobs without confirming. No process.wait loops: intermediate
  commits + parallel next work; rejoin on notify_on_complete.
- Prototypes become production — correctness/organization from day one.
- No special-cased names. Generalize or drop — never re-introduce.
- Telegram drops the last table column — use labeled one-liners.
- Comments and docs are CODE — must match, not mislead (AI reads them).
  Never allow/deny-list as a fix; fix at the source. Read whole files
  exhaustively; never assume a file is fine.
- No mistake post-mortems or repeated apologies: fix it, state the
  correction in one line, move on.
- Challenges wrong conclusions; re-measure on real data. Prefer obvious
  next steps done without asking.
- User-facing reports/updates in ENGLISH (the user can't steer/correct
  otherwise); Chinese only as a supplement.
- gh defaults to upstream zoulasc/racoon2; mine = derekm/racoon2
  (int/gsoc2026); workflow dispatch needs -R derekm/racoon2.
- Prod deploy = STOCK make install /usr/local/racoon2 (enable-pcap/debug);
  never a one-off /tmp/r2prod. Hooks live in sysconfdir hook/. Scratch .sh
  on Windows is CRLF — LF-convert before shipping to the box.

---

## Milestones

### 2026-10-24 — r2dp project landed (recognition)
Recognized the reference to a second repository + CI applying a patch to
racoon2 as an upstream dependency. Identified that this is the r2dp
external-dataplane control protocol: iked/spmd drive an external forwarder
(DPDK) instead of the kernel via a PF_KEY-shaped protocol over a unix
SOCK_SEQPACKET socket. Per the brief: the repo must hold the build/CI so
the patch can be applied to racoon2 as an upstream dependency, and the
implementation must be generic so other dataplane backends can be added
without being upstreamed.

**Correction:** my first framing — "HEAD has advanced past both zips" — was
wrong. A tree diff showed the zips and the git history are *two parallel,
structurally divergent implementations* of the same wire contract, sharing
zero byte-identical files. Neither is an ancestor of the other. This
changed the plan from "rebase incremental changes" (impossible — no
overlapping files) to "re-express features onto the zip lineage's cleaner
control-plane-engine architecture."

### 2026-10-24 — r2dp-interop-harness skill created (compaction anchor)
Captured hard-won live-interop lessons as a reusable skill, so future
sessions don't rediscover them:
- STALE-RESUME trap: iked resumes IKE_SA + child SAs from
  RACOON2_RESUME_DIR on restart; a stale shared dump makes a fresh
  responder skip re-installing into an empty forwarder SAD, so ESP=0.
  Clear the dump and use an isolated per-side resume dir.
- Inner tunnel subnet must be TUNNEL-ONLY; putting it on the bridged outer
  iface makes ping a plain L2 unicast and ESP never reaches the forwarder.
- DPDK net_tap in a Linux bridge delivers to the PMD; the earlier esp=0
  was a /tmp-disk-full misdiagnosis. Check `df -h /tmp` before transferring
  scripts (a starved tmpfs silently null-byte-corrupts scp'd files).
- Read the esp COUNTER VALUE, never a grep match count — every stats line
  literally contains "esp=0".
- ldd first when a racoon2/DPDK binary "starts and dies with empty log"
  (missing libracoon/libr2dp on LD_LIBRARY_PATH).

### 2026-10-25 — authorship rewrite of derekm/r2dp (history)
Rewrote the contributor history of derekm/r2dp main: re-attributed the 65
commits stamped "Mark Wilcox" (whose work was agent-produced, not by that
account) to the agent identity "Terre d'Hermès <derek.p.moore@gmail.com>",
preserving original author AND committer timestamps; left Derek's 20
commits untouched in content. Verified byte-identity of the tip tree before
and after, and confirmed the remote census (20 Derek / 65 Terre) and that
the old tip was absent. Forced-pushed. Safety nets: pre-rewrite backup
branch + tag at the old tip.
- Rule: a history rewrite must be proven in a throwaway clone first, then
  repeated byte-identically on the real repo; verify timestamps survive and
  that only the targeted commits change.

### 2026-10-25/26 — lineage DAG reconstruction
Mapping the true lineage surfaced three artifacts that must be reconciled:
- zip#1 (M0, 8 files, partial: no meson.build, no libr2dp/client.h).
- zip#2 (M0+M1, 29 files, complete: the shared control-plane engine
  libr2dp/cp.c + include/r2dp/cp.h with r2dp_cp_hooks — this is the
  "generic dataplane backends" design; mock-fwd is a hook-less driver).
- mark-cleanroom branch (M0 650b26e → M1 7669f9a → M1.5 f249fda + kfwd),
  and main (85 commits) sharing the same M0 root.
Created a local-only orphan `lineage` branch: root 5361910 (zip1 M0,
byte-identical) → child b57d97f (zip2 M0+M1, byte-identical), verified
per-file hashes with no .DS_Store contamination.

### 2026-10-26 — lineage-DAG CI baseline
Added `.github/workflows/ci.yml` + `tests/ci_dag.sh` committed as d9f3de7:
- The CI builds and tests EVERY commit in the DAG, not just the tip —
  each commit gets its own isolated detached worktree, then a per-commit
  gate.
- Per-commit gate is honest to the snapshot: has meson.build → full
  meson setup/compile/test (milestone 0 needs no DPDK); no meson.build
  (the M0 root ships no libr2dp) → the only self-contained artifact
  (proto.h wire contract, _Static_assert layout) is compiled.
- Windows-specific pitfall recorded: mktemp -d returns an MSYS /tmp path
  that native git can't populate a worktree into — the ubuntu runner
  doesn't share this, but local simulation must use a real Windows path.

---

## Corrections to my own reasoning (kept as lessons, not apologies)

- Assumed tree relationships from commit-message intent instead of
  measuring the trees. The diff is the ground truth: "sibling" not
  "ancestor" was the real topology, and it upended the rebase plan.
- Left a stray `meson test -C build` in ci_dag.sh that would have failed
  the no-meson root; caught it on read-back.
- Windows /tmp vs native-git path mismatch surfaced as a false
  "has_meson=no" in local simulation — the logic was right, the path was
  wrong. Traced to the fork's MSYS/native-git behavior, not the CI logic.

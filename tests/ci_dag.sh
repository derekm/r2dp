#!/usr/bin/env bash
# r2dp lineage-DAG CI: build + test every commit in the lineage graph.
#
# Each commit in the DAG is checked out into its own detached worktree and
# built the way that snapshot can actually build (see "per-commit build").
# Defaults to the *entire* ancestry of origin/lineage (or HEAD); pass a
# space/newline-separated SHA list via DAG_COMMITS to test a subset.
#
# Exit 0 only if every commit configures/compiles/tests; fails on the first
# broken commit with its log printed.
#
# Memory context for this DAG and its commits: docs/memory-links.md
# (cross-references each commit/branch here to AGENT_MEMORY_MILESTONES.md).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

MILESTONE="${MILESTONE:-0}"

# which commits to test: explicit list, else entire lineage history
if [ -n "${DAG_COMMITS:-}" ]; then
  COMMITS="$DAG_COMMITS"
else
  COMMITS="$(git rev-list --reverse HEAD)"
fi

test -n "$COMMITS"

echo "== lineage-DAG CI (milestone $MILESTONE) =="
echo "commits under test:"; printf '%s\n' $COMMITS | sed 's/^/   /'; echo

: > "$ROOT/dag-ci.log"

fail() { echo; echo "FAILED at $1 (see dag-ci.log)"; exit 1; }

for SHA in $COMMITS; do
  SUBJ="$(git log -1 --format='%h %s' "$SHA")"
  echo "== commit $SUBJ =="
  echo "[dag-ci] === $SUBJ ===" >> "$ROOT/dag-ci.log"

  # ---- isolated detached worktree for this snapshot ----
  WT="$(mktemp -d)"
  git worktree add -q --detach "$WT" "$SHA" 2>>"$ROOT/dag-ci.log" || \
    { echo "  (worktree add failed: no tree?)"; git worktree prune; fail "$SHA"; }

  (
    cd "$WT"

    # ---- per-commit build: adapt to what the snapshot ships ----
    if [ -f meson.build ]; then
      # M0+M1 (zip2) and later: full meson build + test.  milestome 0 needs
      # no DPDK; milestone >=1 requires libdpdk (installed in CI for M1+).
      meson setup build -Dmilestone="$MILESTONE" >/dev/null
      meson compile -C build
      meson test -C build --print-errorlogs
    else
      # M0 root (zip1): partial snapshot, no meson.build, no libr2dp.
      # Its mockfwd.c/if_r2dp.c reference headers absent from the tarball;
      # the only self-contained artifact is the wire contract header.
      # Baseline gate: compile proto.h (has _Static_assert layout checks).
      cc -std=gnu11 -Wall -Wextra -Iinclude -fsyntax-only \
         -x c - -o /dev/null <<'EOF' 2>&1
#include "r2dp/proto.h"
int main(void){ return 0; }
EOF
      echo "  (M0 root: proto.h layout check passed)"
    fi
  ) >>"$ROOT/dag-ci.log" 2>&1 || fail "$SHA"

  git worktree remove -f "$WT"
  echo "  OK"
done

echo
echo "ALL DAG COMMITS PASSED"

#!/usr/bin/env bash
# r2dp all-branches CI: build + test EVERY commit on EVERY branch.
#
# The gate lives here (on main) but is not tied to main's source: it walks
# the commit graph of every branch and compiles each commit the way that
# snapshot can actually build.  Meta branches (lineage/agent/usage/site)
# carry no source, so their commits are recorded as SKIP (nothing buildable)
# rather than failed — they're tracking contexts, not code.
#
# Per-commit gate:
#   - has meson.build                    -> meson setup/compile/test (milestone 0, no DPDK)
#   - has include/r2dp/proto.h (no meson) -> gcc -fsyntax-only proto.h layout check
#   - neither                            -> SKIP (meta commit)
#
# Exit 0 only if every code-carrying commit passes; SKIPs are informational.
# Set DAG_COMMITS (space/newline SHAs) to limit scope; else walks all branches.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MILESTONE="${MILESTONE:-0}"
BRANCHES="${BRANCHES:-$(git for-each-ref --format='%(refname:short)' refs/heads | grep -vE 'pre-|contrib-doc' )}"

echo "== r2dp all-branches CI (milestone $MILESTONE) =="
echo "branches: "; printf '%s\n' $BRANCHES | sed 's/^/   /'; echo

# __union of commits across the selected branches, oldest-first, deduped
COMMITS="${DAG_COMMITS:-}"
if [ -z "$COMMITS" ]; then
  COMMITS="$(for b in $BRANCHES; do git rev-list --reverse "$b"; done | awk '!seen[$0]++')"
fi
TOTAL=$(printf '%s\n' $COMMITS | wc -l)
echo "commits under test: $TOTAL"; echo

: > "$ROOT/.ci_all.log"
PASS=0; SKIP=0; FAIL=0

for SHA in $COMMITS; do
  SUBJ="$(git log -1 --format='%h %d %s' "$SHA" 2>/dev/null | cut -c1-100 || echo "$SHA")"
  WT="$(mktemp -d)"
  git worktree add -q --detach "$WT" "$SHA" 2>>"$ROOT/.ci_all.log" || { echo "  WORKTREE-FAIL $SUBJ"; git worktree prune; FAIL=$((FAIL+1)); continue; }
  (
    cd "$WT"
    if [ -f meson.build ]; then
      meson setup build -Dmilestone="$MILESTONE" >/dev/null 2>&1
      meson compile -C build >/dev/null 2>&1
      meson test -C build >/dev/null 2>&1
      echo "BUILD"
    elif [ -f include/r2dp/proto.h ]; then
      cc -std=gnu11 -Wall -Wextra -Iinclude -fsyntax-only -x c - -o /dev/null <<'EOF' >/dev/null 2>&1
#include "r2dp/proto.h"
int main(void){ return 0; }
EOF
      echo "PROTO"
    else
      echo "SKIP-META"
    fi
  ) >>"$ROOT/.ci_all.log" 2>&1
  RC=$?
  case $RC in
    0) PASS=$((PASS+1)); st=pass ;;
    77) SKIP=$((SKIP+1)); st=skip ;;
    *) FAIL=$((FAIL+1)); st=FAIL ;;
  esac
  tag="$(grep -E '^(BUILD|PROTO|SKIP-META)$' "$ROOT/.ci_all.log" | tail -1)"
  printf '  %-5s %s [%s]\n' "$st" "$SUBJ" "${tag:-?}"
  git worktree remove -f "$WT"
done

echo
echo "=== RESULT: PASS=$PASS SKIP=$SKIP FAIL=$FAIL (total $TOTAL) ==="
[ "$FAIL" = 0 ]

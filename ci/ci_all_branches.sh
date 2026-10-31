#!/usr/bin/env bash
# r2dp all-branches CI: build + test the TIP of every branch.
#
# Each tip is built the way that snapshot can build: meson (no DPDK, the
# default options of that tree) when it has a meson.build, a proto.h
# syntax/layout check when it only carries the header, SKIP otherwise
# (meta branches).  Exit 0 only if every code-carrying tip passes.
#   BRANCHES="a b"   limit to these branches (default: every origin/* ref)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
git fetch -q origin '+refs/heads/*:refs/remotes/origin/*' 2>/dev/null || true
BRANCHES="${BRANCHES:-$(git for-each-ref --format='%(refname:lstrip=3)' refs/remotes/origin | grep -vx HEAD)}"
LOG="$ROOT/.ci_all.log"; : >"$LOG"
PASS=0; SKIP=0; FAIL=0

build_tip() {     # cwd = worktree; prints the kind, returns 0 on success
	if [ -f meson.build ]; then
		echo BUILD
		meson setup build && meson compile -C build && meson test -C build
	elif [ -f include/r2dp/proto.h ]; then
		echo PROTO
		printf '#include "r2dp/proto.h"\nint main(void){return 0;}\n' |
		    cc -std=gnu11 -Wall -Wextra -Iinclude -fsyntax-only -x c -
	else
		echo SKIP; return 77
	fi
}

for b in $BRANCHES; do
	sha=$(git rev-parse --short "origin/$b")
	wt=$(mktemp -d)
	if ! git worktree add -q --detach "$wt" "origin/$b" 2>>"$LOG"; then
		printf '  FAIL  %-28s %s (worktree)\n' "$b" "$sha"; FAIL=$((FAIL+1)); continue
	fi
	echo "== $b $sha" >>"$LOG"
	( cd "$wt" && build_tip ) >>"$LOG" 2>&1
	rc=$?
	kind=$(grep -E '^(BUILD|PROTO|SKIP)$' "$LOG" | tail -1)
	case $rc in
		0)  st=pass; PASS=$((PASS+1)) ;;
		77) st=skip; SKIP=$((SKIP+1)) ;;
		*)  st=FAIL; FAIL=$((FAIL+1)) ;;
	esac
	printf '  %-5s %-28s %s [%s]\n' "$st" "$b" "$sha" "$kind"
	git worktree remove -f "$wt"
done
echo "=== RESULT: PASS=$PASS SKIP=$SKIP FAIL=$FAIL ==="
[ "$FAIL" = 0 ]

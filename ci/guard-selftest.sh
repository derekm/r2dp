#!/usr/bin/env bash
# Self-test for the CI regression guards: each guard must pass on a clean
# fixture tree and fail on a tree carrying the thing it forbids.  Runs in a
# throwaway git repo, never in the real worktree.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0

mkrepo() {	# $1 = dir; a minimal clean tree with both guards
	mkdir -p "$1/ci" "$1/src" && cd "$1" || exit 2
	git init -q . && git config user.name ci && git config user.email ci@localhost
	cp "$ROOT/ci/no-cruft-guard.sh" "$ROOT/ci/posix-only-guard.sh" ci/
	printf 'int main(void) { return 0; } /* replay window */\n' >src/a.c
	git add -A && git commit -qm clean
}
expect() {	# $1 = expected rc, $2 = label, rest = command
	want=$1 label=$2; shift 2
	"$@" >/dev/null 2>&1; rc=$?
	if [ "$rc" = "$want" ]; then echo "  ok    $label"
	else echo "  FAIL  $label (rc=$rc, want $want)"; fail=1; fi
}

echo "== guard self-test =="
( mkrepo "$T/clean"
  expect 0 "cruft guard: clean tree" bash ci/no-cruft-guard.sh
  expect 0 "posix guard: clean tree" bash ci/posix-only-guard.sh
  exit $fail ) || fail=1

( mkrepo "$T/cruft"
  touch .DS_Store && git add -f .DS_Store && git commit -qm cruft
  expect 1 "cruft guard: tracked .DS_Store" bash ci/no-cruft-guard.sh
  exit $fail ) || fail=1

( mkrepo "$T/posix"
  tok="Win""32"	# split so this script never spells the token itself
  printf '#ifdef _%s\n#endif\n' "$tok" >src/b.c && git add -A && git commit -qm os
  expect 1 "posix guard: OS marker in a .c file" bash ci/posix-only-guard.sh
  exit $fail ) || fail=1

[ "$fail" = 0 ] && echo "== OK ==" || { echo "== FAIL =="; exit 1; }

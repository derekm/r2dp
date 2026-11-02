#!/usr/bin/env bash
# Regression guard: forbid backup/scratch cruft from ever returning.
#
# We permanently deleted the local-only backup/scratch refs and files:
#   - pre-rewrite-mark-backup, pre-src/{agent,lineage,site,usage}
#   - controlpanel_dev.log, .ci_all.log, __pycache__, *.pyc, .DS_Store
# Those safety-net artifacts outlived their purpose and only clutters the
# branch list, DAG rendering and worktree. This guard fails the build if any
# of them reappear (as a ref) or is committed (as a tracked file), so the
# cleanup is permanent and CI-enforced.
#
# Exit 0 = clean; exit 1 = cruft detected (list what, then fail).
set -u
cd "$(git rev-parse --show-toplevel)"

fail=0

echo "== no-cruft regression guard =="

# 1. Forbidden backup/scratch REFS.
FORBIDDEN_REFS=(
  "refs/heads/pre-rewrite-mark-backup"
  "refs/heads/pre-src/agent"
  "refs/heads/pre-src/lineage"
  "refs/heads/pre-src/site"
  "refs/heads/pre-src/usage"
)
# also any ref starting with refs/heads/pre-* or containing '_backup'
for r in "${FORBIDDEN_REFS[@]}"; do
  if git show-ref --verify --quiet "$r"; then
    echo "  REF PRESENT (forbidden): $r"; fail=1
  fi
done
# sweep for any other 'pre-' prefixed or '*_backup' local branches
git for-each-ref --format='%(refname)' refs/heads | while read -r r; do
  case "$r" in
    refs/heads/pre-*|refs/heads/*_backup)
      echo "  REF PRESENT (forbidden): $r"; fail=1 ;;
  esac
done
# propagate fail from the subshell
if git for-each-ref --format='%(refname)' refs/heads | grep -qE 'refs/heads/(pre-|.*_backup)'; then
  fail=1
fi

# 2. Forbidden scratch files — either TRACKED in git or present in the
#    worktree (a fresh checkout has neither, so both are valid signals).
FORBIDDEN_FILES=(
  ".ci_all.log"
  "controlpanel_dev.log"
  "controlpanel/controlpanel_dev.log"
)
for f in "${FORBIDDEN_FILES[@]}"; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    echo "  TRACKED (forbidden): $f"; fail=1
  fi
  if [ -e "$f" ]; then
    echo "  PRESENT in worktree (forbidden): $f"; fail=1
  fi
done
# any committed __pycache__ / *.pyc / .DS_Store
git ls-files | grep -qE '(^|/)__pycache__/|\.pyc$|\.DS_Store$' && {
  echo "  TRACKED scratch: $(git ls-files | grep -E '(^|/)__pycache__/|\.pyc$|\.DS_Store$' | tr '\n' ' ')"; fail=1; }
# and any present in the worktree
find . -path ./.git -prune -o \( -path '*/__pycache__' -o -name '*.pyc' -o -name '.DS_Store' \) -print 2>/dev/null | grep -q . && {
  echo "  PRESENT scratch: $(find . -path ./.git -prune -o \( -path '*/__pycache__' -o -name '*.pyc' -o -name '.DS_Store' \) -print 2>/dev/null | tr '\n' ' ')"; fail=1; }

if [ "$fail" = 1 ]; then
  echo "== FAIL: backup/scratch cruft detected — remove it (see above) =="
  exit 1
fi
echo "== OK: no backup/scratch cruft =="
exit 0

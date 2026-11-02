#!/usr/bin/env bash
# Regression guard: keep R2DP POSIX/Linux-only.  The project has never had
# Windows/MSVC support and must not gain it.  Fails if the OS-specific terms
# appear in tracked source/docs (excluding the ESP anti-replay "window", which
# is a security feature — matched only on whole-word lowercase 'windows' in
# comments like 'replay window', never 'Windows'/'MSVC'/etc).
#
# Exit 0 = clean; exit 1 = forbidden term found (list it, then fail).
set -u
cd "$(git rev-parse --show-toplevel)"

# Two-term strategy to avoid the ESP anti-replay "window" (a security feature,
#   - Unambiguous OS markers (MSVC, Win32, Win64, MingW, Visual Studio):
#     matched case-insensitively — they can never be legitimate here.
#   - OS *Windows*: matched ONLY as the exact capital-W proper noun "Windows",
#     never the lowercase noun (anti-replay window). Lowercase "windows" is
#     the replay feature and is intentionally allowed.
#
# Docs/generated html are out of scope (prose may mention the dev host).
# Exit 0 = clean; exit 1 = forbidden term found in source.
echo "== POSIX-only regression guard =="
fail=0

# (a) unambiguous OS markers, case-insensitive — must never exist in source
AMBIG='(MSVC|Win32|Win64|MingW|Visual.?Studio)'
hits="$(git grep --no-color -I -i -E "$AMBIG" -- ':!*.md' ':!site/index.html' 2>/dev/null)"
if [ -n "$hits" ]; then
  echo "  FORBIDDEN OS marker in source (case-insensitive):"
  printf '%s\n' "$hits" | head -20
  fail=1
fi

# (b) capital-W "Windows" proper noun only (not the lowercase replay window)
WINHITS="$(git grep --no-color -I -E '\bWindows\b' -- ':!*.md' ':!site/index.html' 2>/dev/null)"
if [ -n "$WINHITS" ]; then
  echo "  FORBIDDEN 'Windows' (proper noun) in source:"
  printf '%s\n' "$WINHITS" | head -20
  fail=1
fi

if [ "$fail" = 1 ]; then
  echo "== FAIL: source tree references Windows/MSVC — remove it (POSIX-only) =="
  exit 1
fi
echo "== OK: source tree is POSIX/Linux-only (no Windows/MSVC) =="
exit 0

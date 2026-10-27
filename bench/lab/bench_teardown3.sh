#!/bin/bash
# bench_teardown3.sh -- PGID-scoped teardown.  Kills each recorded process
# GROUP (kill -- -PGID), so every process and child spawned by the test run is
# torn down together.  PGIDs come from the session file written by
# bench_spawn3.sh; nothing is matched by name/path, so concurrent tests and
# prod /usr/local/racoon2 iked/spmd are never touched.
#
# usage: bench_teardown3.sh <session-file> [list]
set -u
SESS="$1"
[ ! -e "$SESS" ] && { echo "bench_teardown: no session $SESS"; exit 0; }
pgids=""
while read -r g; do
  [ -n "${g:-}" ] || continue
  case " $pgids " in *" $g "*) continue ;; esac
  pgids="$pgids $g "
done < "$SESS"
if [ -z "$pgids" ]; then echo "bench_teardown: empty session $SESS"; exit 0; fi
if [ "${2:-}" = "list" ]; then
  echo "bench_teardown [$SESS] would kill groups:"; printf '%s\n' $pgids
  exit 0
fi
echo "bench_teardown [$SESS] killing process groups:"
for g in $pgids; do
  # GUARD: never signal our own group; never signal a prod group.
  getpgidpid=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')
  [ "$g" = "$getpgidpid" ] && { echo "  skip self-group $g"; continue; }
  # Check group leader cmdline for prod path (belt+braces).
  leader="$g"
  if [ -r "/proc/$leader/cmdline" ] && \
     tr '\0' ' ' < "/proc/$leader/cmdline" 2>/dev/null | grep -q "/usr/local/racoon2"; then
    echo "ABORT: group $g leader is prod -- NOT killing"; exit 3
  fi
  echo "  kill -TERM -$g"
  kill -TERM -- "-$g" 2>/dev/null
done
sleep 1
for g in $pgids; do
  [ -d "/proc/$g" ] && echo "  kill -KILL -$g" && kill -KILL -- "-$g" 2>/dev/null
done
rm -f "$SESS"
echo "bench_teardown: done (prod /usr/local/racoon2 untouched)"

#!/bin/bash
# bench_spawn3.sh -- launch one background lab process in its OWN process
# group (setsid), record that PGID into the session file.  Teardown kills the
# whole group (kill -- -PGID) so the process AND its children/grandchildren
# (e.g. a `sudo ... bash -c` wrapper that forks the real forwarder) are torn
# down together.  PGID-scoped: never by name/path-scan -> concurrent tests and
# prod systemd iked/spmd are safe.
#
# usage: bench_spawn3.sh <session-file> <cmd...>
set -u
SESS="$1"; shift
mkdir -p "$(dirname "$SESS")"
touch "$SESS"
# setsid => new session + process group; leader pid == pgid
setsid "$@" &
child=$!
spawned=$child
if ! grep -qx "$spawned" "$SESS" 2>/dev/null; then
  echo "$spawned" >> "$SESS"
fi
echo "bench_spawn: pgid=$spawned cmd=$*"

#!/usr/bin/env bash
# r2dp-fwd start-up exit-status contract (INIT I2, CONFIG CF1, CRYPTOQ CQ2):
# a bad -n, an unusable control socket path, or (DPDK builds) a broken EAL
# configuration must stop the daemon with a non-zero status, never leave it
# running control-only.  Usage: fwd_cli_test.sh <r2dp-fwd>
set -u
FWD=$1
T=$(mktemp -d "${TMPDIR:-/tmp}/fwdcli.XXXXXX")
trap 'rm -rf "$T"' EXIT
EAL="--no-huge -m 256 --no-pci --no-telemetry --no-shconf --file-prefix r2dpcli$$"
fails=0
# rc WANT CMD...: run with a timeout (a daemon that keeps serving is a fail)
rc() { local want=$1; shift
       timeout 10 "$@" >"$T/out" 2>&1; local r=$?
       if [ "$r" = "$want" ]; then echo "ok   rc=$want: $*"
       else echo "FAIL rc=$r want $want: $*"; cat "$T/out"; fails=$((fails+1)); fi; }
has() { if grep -qF -- "$1" "$T/out"; then echo "ok   output has: $1"
        else echo "FAIL output lacks: $1"; cat "$T/out"; fails=$((fails+1)); fi; }

S=$T/s.sock
for n in abc 0 -1 2x 99999999999 ""; do
	rc 2 "$FWD" -s "$S" -n "$n" $EAL;  has "-n"
done
rc 2 "$FWD" -s "$S" --nh-size 0 $EAL
rc 2 "$FWD" -s "$S" --dp bogus $EAL

# control socket that cannot be served -> exit 1, not a clean exit 0
rc 1 "$FWD" -s "$T/no-such-dir/x.sock" $EAL;  has "listen"
: >"$T/regular"
rc 1 "$FWD" -s "$T/regular" $EAL;             has "listen"
[ -f "$T/regular" ] && echo "ok   regular file left in place" ||
	{ echo "FAIL regular file was removed"; fails=$((fails+1)); }
long="$T/$(printf 'x%.0s' $(seq 120)).sock"
rc 1 "$FWD" -s "$long" $EAL;                  has "too long"

# DPDK builds only: a bad EAL option is a failed start, not control-only.
"$FWD" -s "$T/probe.sock" $EAL --definitely-not-an-eal-option >"$T/out" 2>&1 &
P=$!
for _ in $(seq 50); do kill -0 $P 2>/dev/null || break; sleep 0.1; done
if kill -0 $P 2>/dev/null; then
	kill $P; wait $P 2>/dev/null
	if grep -q "no DPDK build" "$T/out"; then echo "skip bad-EAL case (no DPDK build)"
	else echo "FAIL bad EAL option left the daemon running"; cat "$T/out"; fails=$((fails+1)); fi
else
	wait $P; r=$?
	# r2dp-fwd exits 1; some EAL versions exit from their own argument
	# parser first.  Either way it must be a non-zero exit.
	if [ $r != 0 ]; then echo "ok   rc=$r (non-zero): bad EAL option"
	else echo "FAIL rc=0: bad EAL option"; cat "$T/out"; fails=$((fails+1)); fi
fi

# SHUTDOWN SH1: a second forwarder on a live control socket must fail
# before touching it; the first keeps its endpoint; after the owner dies
# (even SIGKILL) a new one can take over.
CTL=${2:-}
S=$T/one.sock
"$FWD" -s "$S" $EAL --file-prefix r2dpA$$ >"$T/a.out" 2>&1 & A=$!
for _ in $(seq 100); do [ -S "$S" ] && break; sleep 0.1; done
if [ -S "$S" ]; then
	ino=$(stat -c %i "$S")
	rc 1 "$FWD" -s "$S" $EAL --file-prefix r2dpB$$;  has "already serves"
	[ "$(stat -c %i "$S")" = "$ino" ] && kill -0 $A 2>/dev/null &&
		echo "ok   first instance keeps its socket" ||
		{ echo "FAIL second instance replaced the live socket"; fails=$((fails+1)); }
	if [ -n "$CTL" ]; then
		"$CTL" "$S" hello >"$T/out" 2>&1 && echo "ok   first instance still answers" ||
			{ echo "FAIL hello to first instance"; cat "$T/out"; fails=$((fails+1)); }
	fi
	kill -9 $A; wait $A 2>/dev/null
	"$FWD" -s "$S" $EAL --file-prefix r2dpC$$ >"$T/c.out" 2>&1 & C=$!
	ok=0
	for _ in $(seq 100); do
		grep -q "serving" "$T/c.out" && { ok=1; break; }
		kill -0 $C 2>/dev/null || break; sleep 0.1
	done
	[ $ok = 1 ] && echo "ok   replacement takes over after the owner is killed" ||
		{ echo "FAIL no takeover after SIGKILL"; cat "$T/c.out"; fails=$((fails+1)); }
	kill $C 2>/dev/null; wait $C 2>/dev/null
else
	echo "FAIL first instance did not start"; cat "$T/a.out"; fails=$((fails+1))
	kill $A 2>/dev/null; wait $A 2>/dev/null
fi

[ $fails = 0 ] && echo "PASS" || { echo "$fails failure(s)"; exit 1; }

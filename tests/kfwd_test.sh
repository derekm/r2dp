#!/bin/bash
# r2dp-kfwd conformance: drive the kernel-XFRM backend through the r2dp protocol
# and read the kernel's own tables back with `ip xfrm`.  Runs once per control
# loop (poll, and io_uring when built in).  Needs root + iproute2; skips (77) otherwise.
#
#   kfwd_test.sh <r2dp-kfwd> <r2dpctl>
set -u
KFWD="${1:?r2dp-kfwd}"; CTL="${2:?r2dpctl}"
NS=r2kt; D=/tmp/r2dp-kfwd-test
KEY=000102030405060708090a0b0c0d0e0f10111213
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
command -v ip >/dev/null || { echo "SKIP: needs iproute2"; exit 77; }
ip netns add $NS 2>/dev/null && ip netns del $NS 2>/dev/null || { echo "SKIP: cannot create network namespaces"; exit 77; }

rc=0; PID=""
ok()   { echo "  ok   $1"; }
bad()  { echo "  FAIL $1"; rc=1; }
chk()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
cleanup() { [ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null; sleep 0.3; pkill -9 -x r2dp-kfwd 2>/dev/null; ip netns del $NS 2>/dev/null; }
trap cleanup EXIT

xp()  { ip netns exec $NS ip -o xfrm policy; }
xs()  { ip netns exec $NS ip -o xfrm state; }
npol(){ xp | grep -c "^src"; }
c()   { "$CTL" -s "$D/s" "$@" 2>&1; }

# Protocol abuse: each must end with the daemon closing *that* connection.
abuse_garbage() {
	python3 - "$D/s" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); s.settimeout(3)
s.connect(sys.argv[1]); s.send(b"\x5a" * 40)
sys.exit(0 if s.recv(64) == b"" else 1)
PY
}
abuse_oversize() {
	python3 - "$D/s" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); s.settimeout(3)
s.connect(sys.argv[1]); s.send(b"\x00" * 4090)          # larger than a legal message once framed
try:
    sys.exit(0 if s.recv(64) == b"" else 1)
except ConnectionResetError:
    sys.exit(0)
PY
}

run_mode() {
	local io=$1
	echo "== control loop: $io"
	ip netns del $NS 2>/dev/null; ip netns add $NS; ip netns exec $NS ip link set lo up
	rm -rf "$D"; mkdir -p "$D"
	ip netns exec $NS "$KFWD" -s "$D/s" -v --io "$io" >"$D/out" 2>"$D/err" &
	PID=$!
	for _ in $(seq 50); do [ -S "$D/s" ] && break; kill -0 $PID 2>/dev/null || break; sleep 0.1; done
	if ! [ -S "$D/s" ]; then
		if grep -q "built without liburing" "$D/err"; then echo "  skip (kfwd built without liburing)"; return; fi
		cat "$D/err"; bad "kfwd did not start in --io $io mode"; return
	fi

	local h; h=$(c hello); chk "hello answers ($(echo "$h" | grep -o 'features=[0-9a-fx]*'))" 'echo "$h" | grep -q features='

	# ---- policies: the kernel is the oracle ---------------------------------
	c sp-add --dir out --src 10.1.0.0/24 --dst 10.2.0.0/24 --proto 6 --dport 443 --action protect --tun-src 192.0.2.1 --tun-dst 192.0.2.2 --reqid 7 | grep -q "sp-add: ok" || bad "add tcp/443 protect policy"
	c sp-add --dir out --src 10.1.0.0/24 --dst 10.2.0.0/24 --action protect --tun-src 192.0.2.1 --tun-dst 192.0.2.2 | grep -q "sp-add: ok" || bad "add generic protect policy"
	c sp-add --dir in  --src 10.2.0.0/24 --dst 10.1.0.0/24 --action discard | grep -q "sp-add: ok" || bad "add discard policy"
	c sp-add --dir fwd --src 10.2.0.0/24 --dst 10.1.0.0/24 --proto 17 --dport 500 --action bypass | grep -q "sp-add: ok" || bad "add bypass policy"
	chk "kernel holds exactly 4 policies" '[ "$(npol)" = 4 ]'
	P443=$(xp | grep "proto tcp dport 443")
	chk "tcp/443: dir out, ESP tunnel template, endpoints and reqid" \
	    'echo "$P443" | grep -q "dir out" && echo "$P443" | grep -q "tmpl src 192.0.2.1 dst 192.0.2.2" && echo "$P443" | grep -q "proto esp reqid 7 mode tunnel"'
	GEN=$(xp | grep "dir out" | grep -v "dport 443")
	chk "generic policy has reqid 0" 'echo "$GEN" | grep -q "proto esp reqid 0 mode tunnel"'
	chk "discard => action block, dir in, no template" 'xp | grep "dir in" | grep -q "action block" && ! xp | grep "dir in" | grep -q tmpl'
	chk "bypass => dir fwd, udp/500, allow, no template" 'xp | grep "dir fwd" | grep -q "proto udp dport 500" && ! xp | grep "dir fwd" | grep -q tmpl'
	p1=$(echo "$P443" | grep -o "priority [0-9]*" | cut -d' ' -f2); p2=$(echo "$GEN" | grep -o "priority [0-9]*" | cut -d' ' -f2)
	chk "more specific selector gets the stronger (lower) kernel priority ($p1 < $p2)" '[ "${p1:-0}" -lt "${p2:-0}" ]'

	chk "duplicate add -> EEXIST, kernel unchanged" \
	    'c sp-add --dir out --src 10.1.0.0/24 --dst 10.2.0.0/24 --action protect --tun-src 192.0.2.1 --tun-dst 192.0.2.2 | grep -q "File exists" && [ "$(npol)" = 4 ]'
	c sp-add --dir out --src 10.1.0.0/24 --dst 10.2.0.0/24 --action protect --tun-src 192.0.2.1 --tun-dst 192.0.2.2 --reqid 9 --update | grep -q "slid=2" || bad "upsert keeps slid 2"
	chk "upsert replaces in place (reqid 9, still 4 policies)" \
	    '[ "$(npol)" = 4 ] && xp | grep "dir out" | grep -v "dport 443" | grep -q "reqid 9"'
	chk "sp-dump lists all 4 from the engine" '[ "$(c sp-dump | wc -l)" = 4 ]'
	chk "delete by slid removes it from the kernel" 'c sp-del --slid 1 | grep -q "sp-del: ok" && [ "$(npol)" = 3 ] && ! xp | grep -q "dport 443"'
	chk "second delete -> ENOENT" 'c sp-del --slid 1 | grep -q "No such file"'

	# ---- states: either the kernel takes it, or its refusal reaches the client
	if echo "$h" | grep -q "gcm16=1"; then
		chk "SA install succeeds" 'c sa-add --spi 0x1000 --src 192.0.2.1 --dst 192.0.2.2 --key $KEY --esn | grep -q "sa-add: ok"'
		S=$(xs)
		chk "kernel state: spi, aead gcm, ESP tunnel, ESN" \
		    'echo "$S" | grep -q "spi 0x00001000" && echo "$S" | grep -q "rfc4106(gcm(aes))" && echo "$S" | grep -q "mode tunnel" && echo "$S" | grep -qi "esn"'
		chk "duplicate SA -> EEXIST" 'c sa-add --spi 0x1000 --src 192.0.2.1 --dst 192.0.2.2 --key $KEY | grep -q "File exists"'
		chk "SA delete reaches the kernel" 'c sa-del --spi 0x1000 --dst 192.0.2.2 | grep -q "sa-del: ok" && [ -z "$(xs)" ]'
	else
		echo "  note: this kernel cannot install AES-GCM ESP states (kfwd's probe said so); checking refusal handling"
		e1=$(c sa-add --spi 0x1000 --src 192.0.2.1 --dst 192.0.2.2 --key $KEY | grep -v '^$' | tail -1)
		e2=$(c sa-add --spi 0x1000 --src 192.0.2.1 --dst 192.0.2.2 --key $KEY | grep -v '^$' | tail -1)
		chk "kernel's refusal reaches the client ('$e1')" '[ -n "$e1" ] && ! echo "$e1" | grep -q "ok"'
		chk "refused SA is not committed: retry fails the same way, never EEXIST" '[ "$e1" = "$e2" ] && ! echo "$e2" | grep -q "File exists"'
		chk "kernel state table stays empty" '[ -z "$(xs)" ]'
		chk "kernel's own explanation is logged" 'grep -q "NEWSA.*not found\|NEWSA.*Requested" "$D/err"'
	fi

	# ---- robustness of the control loop -------------------------------------
	n=0; for i in $(seq 60); do c hello | grep -q features= && n=$((n+1)); done
	chk "60 connect/serve/disconnect cycles ($n ok)" '[ $n = 60 ]'
	chk "garbage on the socket drops only that client, others unaffected" 'abuse_garbage && c hello | grep -q features='
	chk "oversized datagram is refused, daemon survives" 'abuse_oversize && c hello | grep -q features='
	chk "daemon alive" 'kill -0 $PID 2>/dev/null'
	kill -TERM $PID; for _ in $(seq 30); do kill -0 $PID 2>/dev/null || break; sleep 0.1; done
	chk "exits on SIGTERM" '! kill -0 $PID 2>/dev/null'
	PID=""
}

run_mode poll
run_mode uring
[ $rc = 0 ] && echo "PASS: r2dp-kfwd translates r2dp to XFRM faithfully under both control loops" || echo "FAILED (logs in $D)"
exit $rc

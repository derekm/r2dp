#!/usr/bin/env bash
# Kernel XFRM backend (r2dp-fwd --dp kernel) through the r2dp socket:
# startup probe, windows > 32 (bitmap replay state), dir from v2, NEWSA
# refusal leaves nothing behind, SP upsert that moves the selector, delete,
# and --dp-cleanup on exit.  Re-execs itself in a user+net namespace;
# SKIPs (77) where that or the kernel's ESP support is unavailable.
set -u
FWD=$1 CTL=$2
# R2DP_REQUIRE_KERNEL=1 (CI kernel lane): a SKIP condition is a failure
skip() { echo "SKIP: $*"; [ -n "${R2DP_REQUIRE_KERNEL:-}" ] && exit 1; exit 77; }
if [ "$(id -u)" != 0 ]; then
	unshare -Urnm true 2>/dev/null || skip "no user namespaces"
	exec unshare -Urnm --propagation private "$0" "$@"
fi
command -v ip >/dev/null || skip "no iproute2"
ip link set lo up
T=$(mktemp -d "${TMPDIR:-/tmp}/kfwd.XXXXXX")
"$FWD" -s "$T/s.sock" --dp kernel --dp-cleanup >"$T/fwd.out" 2>&1 & P=$!
trap 'kill $P 2>/dev/null; wait $P 2>/dev/null; rm -rf "$T"' EXIT
for _ in $(seq 50); do [ -S "$T/s.sock" ] && break; kill -0 $P 2>/dev/null || break; sleep 0.1; done
if ! [ -S "$T/s.sock" ]; then
	grep -q "accepts no ESP transform" "$T/fwd.out" && skip "kernel has no ESP"
	cat "$T/fwd.out"; echo "FAIL: forwarder did not start"; exit 1
fi
fails=0
chk() { local d=$1; shift; if "$@" >/dev/null 2>&1; then echo "ok   $d"; else echo "FAIL $d"; fails=$((fails+1)); fi; }
C="$CTL $T/s.sock"
K=000102030405060708090a0b0c0d0e0f10111213

chk "probe advertised AES-GCM-16" sh -c "$C hello | grep -q '^enc_caps:.* 20\b'"
chk "inbound SA, wsize=128" $C sa-add dir=in spi=0x1000 src=192.0.2.2 dst=192.0.2.1 enc=aes-gcm-16 key=$K wsize=128
chk "kernel holds a 128-packet bitmap window" sh -c "ip -d xfrm state get src 192.0.2.2 dst 192.0.2.1 proto esp spi 0x1000 | grep -Eq 'replay-window 128|window 128'"
chk "default window (r2dpctl: 64)" $C sa-add dir=in spi=0x1001 src=192.0.2.2 dst=192.0.2.1 enc=aes-gcm-16 key=$K
chk "  ... and the kernel shows 64" sh -c "ip -d xfrm state get src 192.0.2.2 dst 192.0.2.1 proto esp spi 0x1001 | grep -Eq 'replay-window 64|window 64'"
chk "wsize=0: anti-replay off" $C sa-add dir=in spi=0x1003 src=192.0.2.2 dst=192.0.2.1 enc=aes-gcm-16 key=$K wsize=0
chk "  ... and the kernel shows replay-window 0" sh -c "ip -d xfrm state get src 192.0.2.2 dst 192.0.2.1 proto esp spi 0x1003 | grep -q 'replay-window 0'"
chk "outbound SA (dir=out): no replay window" $C sa-add dir=out spi=0x2000 src=192.0.2.1 dst=192.0.2.2 enc=aes-gcm-16 key=$K
chk "  ... kernel shows replay-window 0" sh -c "ip -d xfrm state get src 192.0.2.1 dst 192.0.2.2 proto esp spi 0x2000 | grep -q 'replay-window 0'"
chk "bad key length refused with the kernel's errno" sh -c "$C sa-add dir=in spi=0x1002 src=192.0.2.2 dst=192.0.2.1 enc=aes-gcm-16 key=0001 2>&1 | grep -q 'Invalid argument'"
chk "  ... and nothing half-installed" sh -c "! ip xfrm state get src 192.0.2.2 dst 192.0.2.1 proto esp spi 0x1002"
chk "SP add" $C sp-add slid=5 dir=out action=protect src=10.2.0.0/24 dst=10.1.0.0/24 tsrc=192.0.2.1 tdst=192.0.2.2
chk "  ... in the kernel" sh -c "ip xfrm policy list dir out | grep -q 'src 10.2.0.0/24 dst 10.1.0.0/24'"
chk "SP upsert (same selector) PROTECT -> DISCARD" $C sp-add dir=out action=discard src=10.2.0.0/24 dst=10.1.0.0/24 update
chk "  ... replaced in place: one policy, action block" sh -c "[ \$(ip xfrm policy list dir out | grep -c 'dst 10.1.0.0/24') = 1 ] && ip xfrm policy list dir out | grep -q 'action block'"
chk "SP upsert back to PROTECT" $C sp-add dir=out action=protect src=10.2.0.0/24 dst=10.1.0.0/24 tsrc=192.0.2.1 tdst=192.0.2.2 update
chk "more specific policy gets a lower kernel priority" sh -c "$C sp-add slid=6 dir=out action=discard src=10.2.0.5/32 dst=10.1.0.0/24 &&
    p1=\$(ip xfrm policy list dir out | grep -A1 'src 10.2.0.5/32' | grep -o 'priority [0-9]*' | cut -d' ' -f2) &&
    p2=\$(ip xfrm policy list dir out | grep -A1 'src 10.2.0.0/24' | grep -o 'priority [0-9]*' | cut -d' ' -f2) &&
    [ \"\$p1\" -lt \"\$p2\" ]"
chk "SP delete" $C sp-del slid=6
chk "SA delete" $C sa-del spi=0x1001 dst=192.0.2.1
chk "  ... gone from the kernel" sh -c "! ip xfrm state get src 192.0.2.2 dst 192.0.2.1 proto esp spi 0x1001"
kill -TERM $P; wait $P 2>/dev/null
chk "cleanup on exit: no states left" sh -c "[ -z \"\$(ip xfrm state list)\" ]"
chk "cleanup on exit: no policies left" sh -c "[ -z \"\$(ip xfrm policy list)\" ]"
chk "cleanup reported" grep -q "cleanup removed 3 SA(s), 1 SP(s)" "$T/fwd.out"
[ $fails = 0 ] && echo "kfwd_test: OK" || { echo "kfwd_test: $fails failures"; cat "$T/fwd.out"; }
exit $((fails != 0))

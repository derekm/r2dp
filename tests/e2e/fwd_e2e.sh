#!/bin/bash
# M1 interop test: r2dp-fwd (DPDK, AES-GCM ESP tunnel) vs an independent ESP
# implementation (scapy + cryptography), with a real kernel host on the red side.
# (The sandbox kernel has no ESP/GCM, so the kernel cannot be the oracle here;
#  on a normal Linux host you can additionally cross-check against `ip xfrm`.)
#
#   ns "peer"  scapy ESP gateway 192.0.2.2   (veth vpb)
#   ns "fwd"   r2dp-fwd, af_packet ports vfb (black) / vfr (red), tunnel endpoint 192.0.2.1
#   ns "host"  kernel host 10.2.0.2 behind the forwarder (veth vrr)
#
#   fwd_e2e.sh <r2dp-fwd> <r2dpctl>       (root, iproute2, scapy + cryptography)
#   env: PHASES="positive window negative"  STATS_AFTER=1
set -u
FWD="${1:?r2dp-fwd}"; CTL="${2:?r2dpctl}"
HERE="$(cd "$(dirname "$0")" && pwd)"
D=/tmp/r2dp-fwd-e2e; NSP=r2fp; NSF=r2ff; NSH=r2fh
K1=000102030405060708090a0b0c0d0e0f10111213     # peer->fwd (AES-128 key + 4B salt)
K2=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3     # fwd->peer
fail() { echo "FAIL: $*"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
command -v ip >/dev/null && python3 -c "import scapy, cryptography" 2>/dev/null || { echo "SKIP: needs iproute2 + scapy + cryptography"; exit 77; }

cleanup() {
	[ -n "${FPID:-}" ] && kill -TERM "$FPID" 2>/dev/null; sleep 0.3
	pkill -9 -x r2dp-fwd 2>/dev/null          # -x: exact name, never matches this script's own command line
	for n in $NSP $NSF $NSH; do ip netns del $n 2>/dev/null; done
}
trap cleanup EXIT
cleanup; rm -rf "$D" /var/run/dpdk/r2dpfwd; mkdir -p "$D"

for n in $NSP $NSF $NSH; do ip netns add $n; ip netns exec $n ip link set lo up; done
ip link add vpb type veth peer name vfb; ip link set vpb netns $NSP; ip link set vfb netns $NSF
ip link add vfr type veth peer name vrr; ip link set vfr netns $NSF; ip link set vrr netns $NSH
ip netns exec $NSP ip link set vpb up; ip netns exec $NSF ip link set vfb up
ip netns exec $NSF ip link set vfr up;  ip netns exec $NSH ip link set vrr up
mac() { ip netns exec "$1" cat /sys/class/net/"$2"/address; }
PMAC=$(mac $NSP vpb); BMAC=$(mac $NSF vfb); RMAC=$(mac $NSF vfr); HMAC=$(mac $NSH vrr)

# red host: a plain kernel host that answers pings and routes the far subnet via the forwarder
ip netns exec $NSH ip addr add 10.2.0.2/24 dev vrr
ip netns exec $NSH ip route add 10.1.0.0/24 via 10.2.0.1
ip netns exec $NSH ip neigh replace 10.2.0.1 lladdr "$RMAC" dev vrr nud permanent

ip netns exec $NSF "$FWD" -l 0 --no-huge -m 256 --no-pci --no-telemetry --file-prefix r2dpfwd \
	--vdev=net_af_packet0,iface=vfb --vdev=net_af_packet1,iface=vfr --vdev=crypto_openssl0 \
	-- --sock "$D/fwd.sock" --local 192.0.2.1 -v \
	--route "192.0.2.0/24,black,$PMAC" --route "10.2.0.0/24,red,$HMAC" >"$D/fwd.out" 2>"$D/fwd.err" &
FPID=$!
for _ in $(seq 100); do
	[ -S "$D/fwd.sock" ] && break
	kill -0 $FPID 2>/dev/null || { cat "$D/fwd.err"; fail "forwarder died"; }
	sleep 0.1
done
[ -S "$D/fwd.sock" ] || { cat "$D/fwd.err"; fail "forwarder control socket never appeared"; }
c() { "$CTL" -s "$D/fwd.sock" "$@"; }

# program the forwarder purely through the r2dp protocol
c hello | grep -q "gcm16=1" || fail "forwarder does not advertise AES-GCM-16"
c sa-add --spi 0x1000 --src 192.0.2.2 --dst 192.0.2.1 --key $K1 | grep -q "sa-add: ok" || fail "inbound SA rejected"
c sa-add --spi 0x2000 --src 192.0.2.1 --dst 192.0.2.2 --key $K2 | grep -q "sa-add: ok" || fail "outbound SA rejected"
c sp-add --dir in  --src 10.1.0.0/24 --dst 10.2.0.0/24 --action protect --tun-src 192.0.2.2 --tun-dst 192.0.2.1 | grep -q slid || fail "in SP rejected"
c sp-add --dir out --src 10.2.0.0/24 --dst 10.1.0.0/24 --action protect --tun-src 192.0.2.1 --tun-dst 192.0.2.2 | grep -q slid || fail "out SP rejected"

peer() { ip netns exec $NSP python3 "$HERE/fwd_peer.py" vpb "$PMAC" "$BMAC" $K1 $K2 "$1"; }
dump_stats() { kill -USR1 $FPID; sleep 0.5; grep -E "^(stats|drops):" "$D/fwd.out" | tail -2; }

rc=0
for ph in ${PHASES:-positive window negative}; do
	echo "== phase: $ph"; peer $ph || rc=1
	[ -n "${STATS_AFTER:-}" ] && dump_stats
done

echo "== forwarder counters (exact: every packet must be accounted for)"
STATS=$(dump_stats | tr '\n' ' ')
val() { echo "$STATS" | grep -o " $1=[0-9]*" | tail -1 | cut -d= -f2; }
eq() { v=$(val "$1"); if [ "${v:-x}" = "$2" ]; then echo "  ok   $1=$v"; else echo "  FAIL $1=${v:-?} (expected $2)"; rc=1; fi; }
if [ -z "${PHASES:-}" ]; then
	# 15 positive + 4 accepted in the window phase + 1 post-garbage control = 20 round trips
	eq esp_in 20; eq esp_out 20; eq tx_red 20; eq tx_black 20
	eq replay 3; eq auth 2; eq no_sa 1; eq policy 2; eq bad_esp 1
	# nothing else may have been dropped
	for z in bad_ip ttl no_route no_sp_sa too_big seq nobuf crypto local bypass discard; do eq $z 0; done
fi
kill -0 $FPID 2>/dev/null || { echo "  FAIL forwarder crashed"; rc=1; }
[ $rc = 0 ] && echo "PASS: AES-GCM ESP tunnel interoperates with an independent implementation" || echo "FAILED (logs in $D)"
exit $rc

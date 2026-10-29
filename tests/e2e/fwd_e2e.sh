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
#
#   BACKEND=kernel fwd_e2e.sh <r2dp-kfwd> <r2dpctl>
#       Runs the *same* scapy suite against the Linux kernel dataplane (r2dp-kfwd
#       programming XFRM) as the reference.  Needs a kernel with ESP + AES-GCM;
#       skips (77) if the canary state cannot be installed.  Exact DPDK counters
#       are not asserted in this mode.  NOTE: written but never run to completion
#       (the development sandbox kernel has no ESP/GCM), expect to debug it once.
set -u
FWD="${1:?r2dp-fwd}"; CTL="${2:?r2dpctl}"
HERE="$(cd "$(dirname "$0")" && pwd)"
D=/tmp/r2dp-fwd-e2e; NSP=r2fp; NSF=r2ff; NSH=r2fh
K1=000102030405060708090a0b0c0d0e0f10111213     # peer->fwd (AES-128 key + 4B salt)
K2=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3     # fwd->peer
K3=3031323334353637383940414243444546474849     # ESN pair, peer->fwd  (keep in sync with fwd_peer.py)
K4=b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3     # ESN pair, fwd->peer
K5=5051525354555657585960616263646566676869     # NAT-T pair, peer->fwd (keep in sync with fwd_peer.py)
K6=d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3     # NAT-T pair, fwd->peer
BACKEND="${BACKEND:-dpdk}"
fail() { echo "FAIL: $*"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
command -v ip >/dev/null && python3 -c "import scapy, cryptography" 2>/dev/null || { echo "SKIP: needs iproute2 + scapy + cryptography"; exit 77; }

cleanup() {
	[ -n "${FPID:-}" ] && kill -TERM "$FPID" 2>/dev/null; sleep 0.3
	pkill -9 -x r2dp-fwd 2>/dev/null          # -x: exact name, never matches this script's own command line
	pkill -9 -x r2dp-kfwd 2>/dev/null
	for n in $NSP $NSF $NSH; do ip netns del $n 2>/dev/null; done
}
trap cleanup EXIT
if [ "$BACKEND" = kernel ]; then      # canary: can this kernel hold an AES-GCM ESP state at all?
	ip netns add r2canary 2>/dev/null
	if ! ip netns exec r2canary ip xfrm state add src 192.0.2.254 dst 192.0.2.253 proto esp spi 0x1 mode tunnel \
	     aead 'rfc4106(gcm(aes))' 0x000102030405060708090a0b0c0d0e0f10111213 128 >/dev/null 2>&1; then
		ip netns del r2canary 2>/dev/null; echo "SKIP: kernel cannot install AES-GCM ESP states (no esp4/gcm)"; exit 77
	fi
	ip netns del r2canary 2>/dev/null
fi
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

if [ "$BACKEND" = kernel ]; then
	# the kernel is the gateway: addresses, forwarding, static neighbours (scapy does not do ARP)
	ip netns exec $NSF ip addr add 192.0.2.1/24 dev vfb; ip netns exec $NSF ip addr add 10.2.0.1/24 dev vfr
	ip netns exec $NSF sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
	ip netns exec $NSF ip neigh replace 192.0.2.2 lladdr "$PMAC" dev vfb nud permanent
	ip netns exec $NSF ip route add 10.1.0.0/24 via 192.0.2.2 dev vfb
	ip netns exec $NSF "$FWD" -s "$D/fwd.sock" -v >"$D/fwd.out" 2>"$D/fwd.err" &
else
	ip netns exec $NSF "$FWD" -l 0 --no-huge -m 256 --no-pci --no-telemetry --file-prefix r2dpfwd \
		--vdev=net_af_packet0,iface=vfb --vdev=net_af_packet1,iface=vfr --vdev=crypto_openssl0 \
		-- --sock "$D/fwd.sock" --local 192.0.2.1 -v \
		--route "192.0.2.0/24,black,$PMAC" --route "10.2.0.0/24,red,$HMAC" >"$D/fwd.out" 2>"$D/fwd.err" &
fi
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
[ "$BACKEND" = kernel ] && c sp-add --dir fwd --src 10.1.0.0/24 --dst 10.2.0.0/24 --action protect --tun-src 192.0.2.2 --tun-dst 192.0.2.1 | grep -q slid || { [ "$BACKEND" != kernel ] || fail "fwd SP rejected"; }
c sa-add --spi 0x1000 --src 192.0.2.2 --dst 192.0.2.1 --key $K1 | grep -q "sa-add: ok" || fail "inbound SA rejected"
c sa-add --spi 0x2000 --src 192.0.2.1 --dst 192.0.2.2 --key $K2 | grep -q "sa-add: ok" || fail "outbound SA rejected"
c sp-add --dir in  --src 10.1.0.0/24 --dst 10.2.0.0/24 --action protect --tun-src 192.0.2.2 --tun-dst 192.0.2.1 | grep -q slid || fail "in SP rejected"
c sp-add --dir out --src 10.2.0.0/24 --dst 10.1.0.0/24 --action protect --tun-src 192.0.2.1 --tun-dst 192.0.2.2 | grep -q slid || fail "out SP rejected"

peer() { ip netns exec $NSP python3 "$HERE/fwd_peer.py" vpb "$PMAC" "$BMAC" $K1 $K2 "$1"; }
dump_stats() { kill -USR1 $FPID; sleep 0.5; grep -E "^(stats|drops):" "$D/fwd.out" | tail -2; }

rc=0
# AES-CBC + HMAC combos: "<--integ> <auth key bytes> <aes key bytes>", keys derived from the index (see fwd_peer.py)
CBC_COMBOS=("sha1 20 16" "sha256 32 16" "sha384 48 16" "sha512 64 16" "sha256 32 24" "sha256 32 32")
kgen() { local out="" i; for ((i = 0; i < $2; i++)); do out+=$(printf '%02x' $(( ($1 + i * $3) & 255 ))); done; echo "$out"; }
cbc_install() {   # $1 = combo index
	set -- $1 ${CBC_COMBOS[$1]}; local idx=$1 integ=$2 akl=$3 ekl=$4 spi_in=$((0x7000 + 2 * $1)) spi_out=$((0x7001 + 2 * $1))
	c sa-add --spi $spi_in  --src 192.0.2.2 --dst 192.0.2.1 --enc cbc --integ $integ --key $(kgen $((idx*13+1)) $ekl 7) --akey $(kgen $((idx*13+5)) $akl 11) | grep -q "sa-add: ok" || fail "CBC combo $idx inbound SA rejected"
	c sa-add --spi $spi_out --src 192.0.2.1 --dst 192.0.2.2 --enc cbc --integ $integ --key $(kgen $((idx*13+3)) $ekl 7) --akey $(kgen $((idx*13+9)) $akl 11) | grep -q "sa-add: ok" || fail "CBC combo $idx outbound SA rejected"
}
PH_ALL="positive window negative esn natt"; for i in "${!CBC_COMBOS[@]}"; do PH_ALL+=" cbc$i"; done
for ph in ${PHASES:-$PH_ALL}; do
	case "$ph" in cbc[0-9]*) cbc_install "${ph#cbc}" ;; esac
	if [ "$ph" = natt ]; then
		c sa-add --spi 0x5000 --src 192.0.2.2 --dst 192.0.2.1 --key $K5 --natt | grep -q "sa-add: ok" || fail "NAT-T inbound SA rejected"
		c sa-add --spi 0x6000 --src 192.0.2.1 --dst 192.0.2.2 --key $K6 --natt | grep -q "sa-add: ok" || fail "NAT-T outbound SA rejected"
	fi
	if [ "$ph" = esn ]; then   # last on purpose: the newest outbound SA wins, so the earlier phases must be done
		c sa-add --spi 0x3000 --src 192.0.2.2 --dst 192.0.2.1 --key $K3 --esn | grep -q "sa-add: ok" || fail "ESN inbound SA rejected"
		c sa-add --spi 0x4000 --src 192.0.2.1 --dst 192.0.2.2 --key $K4 --esn | grep -q "sa-add: ok" || fail "ESN outbound SA rejected"
	fi
	echo "== phase: $ph"; peer $ph || rc=1
	[ -n "${STATS_AFTER:-}" ] && dump_stats
done

echo "== forwarder counters (exact: every packet must be accounted for)"
[ "$BACKEND" = dpdk ] && STATS=$(dump_stats | tr '\n' ' ') || echo "  (kernel backend: counters not asserted)"
val() { echo "$STATS" | grep -o " $1=[0-9]*" | tail -1 | cut -d= -f2; }
eq() { v=$(val "$1"); if [ "${v:-x}" = "$2" ]; then echo "  ok   $1=$v"; else echo "  FAIL $1=${v:-?} (expected $2)"; rc=1; fi; }
if [ -z "${PHASES:-}" ] && [ "$BACKEND" = dpdk ]; then
	# 15 positive + 4 window + 1 post-garbage control + 7 ESN + 2 NAT-T = 29 complete round trips, plus one NAT-T
	# request that was decrypted and forwarded but whose reply was too big (esp_in/tx_red = 30); then CBC+HMAC:
	# 4 combos x 8 sizes + 2 combos x 2 sizes = 36 more complete round trips
	eq esp_in 66; eq esp_out 65; eq tx_red 66; eq tx_black 65
	# replay: 3 (window) + 1 (ESN); auth: 2 (negative) + 2 (ESN wrong-high / far-future)
	# CBC hostile input: flipped ciphertext, ICV and IV bits = 3 more auth failures
	eq replay 4; eq auth 7; eq no_sa 1; eq policy 2
	# bad_esp: 1 truncated + 2 NAT-T encapsulation mismatches; local: the IKE-marker datagram (no exception path here)
	# (+1 bad_esp: CBC ciphertext that is not a multiple of the block size)
	eq bad_esp 4; eq too_big 1; eq local 1; eq natt_keepalive 1
	# nothing else may have been dropped
	for z in bad_ip ttl no_route no_sp_sa seq nobuf crypto bypass discard expired; do eq $z 0; done
fi
kill -0 $FPID 2>/dev/null || { echo "  FAIL forwarder crashed"; rc=1; }
[ $rc = 0 ] && echo "PASS ($BACKEND): AES-GCM ESP tunnel interoperates with an independent implementation" || echo "FAILED (logs in $D)"
exit $rc

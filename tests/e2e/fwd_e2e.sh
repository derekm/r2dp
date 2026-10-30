#!/bin/bash
# Data-plane interop test: r2dp-fwd (DPDK, rte_ipsec AES-GCM ESP tunnel) vs an
# independent ESP implementation (scapy + cryptography), with the kernel as
# the plaintext host.  Adapted from the upstream prototype's harness.
#
#   r2o  outer tap (net_tap0): fwd_peer.py plays the remote gateway 192.0.2.2
#   r2i  inner tap (net_tap1): the kernel is host 10.2.0.2 behind the
#        forwarder (tunnel endpoint 192.0.2.1)
#
#   fwd_e2e.sh <r2dp-fwd> <r2dpctl>
#   env: PYTHON (python with scapy + cryptography; default python3)
#        R2DP_E2E_DIR scratch dir (default: a fresh mktemp -d)
#        PHASES="positive window negative" (subset => counters not asserted)
#        BACKEND=dpdk|kernel  (kernel: r2dp-fwd with the XFRM data plane)
#
# Needs root in its own network namespace.  Unprivileged:
#   unshare -Urnm --propagation private bash -c \
#     'mount -t tmpfs none /run && tests/e2e/fwd_e2e.sh FWD CTL'
set -u
FWD="${1:?r2dp-fwd}"; CTL="${2:?r2dpctl}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"
BACKEND="${BACKEND:-dpdk}"
K1=000102030405060708090a0b0c0d0e0f10111213     # peer->fwd (AES-128 key + 4B salt)
K2=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3     # fwd->peer
PMAC=02:00:00:00:00:02                          # the scapy peer's MAC
fail() { echo "FAIL: $*"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root (run under unshare -Urnm)"; exit 77; }
command -v ip >/dev/null && "$PY" -c "import scapy, cryptography" 2>/dev/null ||
	{ echo "SKIP: needs iproute2 + scapy + cryptography (set PYTHON)"; exit 77; }
# refuse to run in the host's namespace: we add addresses and routes
[ -n "${R2DP_E2E_ANY_NETNS:-}" ] || [ "$(ip -o link | grep -cv ': lo:')" = 0 ] ||
	fail "run in a fresh network namespace (unshare -Urnm), or set R2DP_E2E_ANY_NETNS=1"

if [ -n "${R2DP_E2E_DIR:-}" ]; then
	D=$R2DP_E2E_DIR; rm -rf "$D"; mkdir -p "$D"
else
	D=$(mktemp -d "${TMPDIR:-/tmp}/r2dp-fwd-e2e.XXXXXX")
fi
[ -d "$D" ] && [ -w "$D" ] && [ -z "$(ls -A "$D")" ] || fail "cannot create a fresh scratch dir $D"

cleanup() { [ -n "${FPID:-}" ] && kill -TERM "$FPID" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

ip link set lo up
echo 1 >/proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null     # no ND/MLD noise
echo 1 >/proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null
HOST_TTL=$(cat /proc/sys/net/ipv4/ip_default_ttl)

if [ "$BACKEND" = kernel ]; then
	# the kernel is the tunnel endpoint AND the protected host (10.2.0.2 on
	# lo); the scapy peer sits behind the r2o/r2ok veth pair
	ip link add r2o type veth peer name r2ok
	ip link set r2o up; ip link set r2ok up
	ip addr add 192.0.2.1/24 dev r2ok
	"$FWD" -s "$D/fwd.sock" --dp kernel --dp-cleanup -v >"$D/fwd.out" 2>&1 &
else
	"$FWD" -s "$D/fwd.sock" -l 0,1 --no-huge -m 512 --no-pci --no-telemetry \
	    --file-prefix "r2e2e$$" --vdev=net_tap0,iface=r2o --vdev=net_tap1,iface=r2i \
	    --vdev=crypto_openssl0 >"$D/fwd.out" 2>&1 &
fi
FPID=$!
for _ in $(seq 100); do
	[ -S "$D/fwd.sock" ] && break
	kill -0 $FPID 2>/dev/null || { cat "$D/fwd.out"; fail "forwarder died"; }
	sleep 0.1
done
[ -S "$D/fwd.sock" ] || { cat "$D/fwd.out"; fail "control socket never appeared"; }
if [ "$BACKEND" = dpdk ]; then
	grep -q "DPDK dataplane ready" "$D/fwd.out" || { cat "$D/fwd.out"; fail "DPDK data plane did not come up"; }
	# the plaintext host behind the forwarder: answers pings, routes the
	# far subnet into the inner tap
	ip addr add 10.2.0.2/24 dev r2i
	ip route add 10.1.0.0/24 via 10.2.0.1 dev r2i
	ip neigh replace 10.2.0.1 lladdr 02:00:00:00:00:99 dev r2i nud permanent
else
	grep -q "kernel XFRM dataplane ready" "$D/fwd.out" || { cat "$D/fwd.out"; fail "XFRM data plane did not come up"; }
	ip addr add 10.2.0.2/32 dev lo
	ip route add 10.1.0.0/24 via 192.0.2.2 dev r2ok src 10.2.0.2
	ip neigh replace 192.0.2.2 lladdr $PMAC dev r2ok nud permanent
fi
# (not /sys/class/net: under unshare -n without a sysfs remount it shows
# the parent namespace)
[ "$BACKEND" = kernel ] && R2O_PEER=r2ok || R2O_PEER=r2o
FMAC=$(ip -o link show $R2O_PEER | grep -o 'link/ether [0-9a-f:]*' | cut -d' ' -f2)
[ -n "$FMAC" ] || fail "no r2o interface"

c() { "$CTL" "$D/fwd.sock" "$@"; }
c hello >"$D/hello" || fail "hello"
grep -qw 20 <(sed -n 's/^enc_caps://p' "$D/hello") || fail "forwarder does not advertise AES-GCM-16"
c sa-add dir=in  spi=0x1000 src=192.0.2.2 dst=192.0.2.1 enc=aes-gcm-16 key=$K1 >/dev/null || fail "inbound SA rejected"
c sa-add dir=out spi=0x2000 src=192.0.2.1 dst=192.0.2.2 enc=aes-gcm-16 key=$K2 >/dev/null || fail "outbound SA rejected"
c sp-add slid=1 dir=in  action=protect src=10.1.0.0/24 dst=10.2.0.0/24 tsrc=192.0.2.2 tdst=192.0.2.1 >/dev/null || fail "in SP rejected"
c sp-add slid=2 dir=out action=protect src=10.2.0.0/24 dst=10.1.0.0/24 tsrc=192.0.2.1 tdst=192.0.2.2 >/dev/null || fail "out SP rejected"

# Nothing routes the inner reply on its way back (the DPDK forwarder is a
# bump in the wire; with the kernel backend the host is the endpoint), so
# it reaches the peer with the host's own default TTL.
RTTL=$HOST_TTL
peer() { "$PY" "$HERE/fwd_peer.py" r2o "$PMAC" "$FMAC" $K1 $K2 "$1" $RTTL; }
dump_stats() {
	local n; n=$(grep -c "r2dp-fwd: drops" "$D/fwd.out")
	kill -USR1 $FPID
	for _ in $(seq 50); do [ "$(grep -c "r2dp-fwd: drops" "$D/fwd.out")" -gt "$n" ] && break; sleep 0.1; done
	grep -E "r2dp-fwd: (stats .*spd_fail|drops)" "$D/fwd.out" | tail -2
}

rc=0
for ph in ${PHASES:-positive window negative}; do
	echo "== phase: $ph"; peer $ph || rc=1
done

if [ -z "${PHASES:-}" ] && [ "$BACKEND" = dpdk ]; then
	echo "== forwarder counters (exact: every packet is accounted for)"
	STATS=" $(dump_stats | tr '\n' ' ')"
	echo "  $STATS"
	val() { echo "$STATS" | grep -o " $1=[0-9]*" | tail -1 | cut -d= -f2; }
	eq() { local v; v=$(val "$1"); if [ "${v:-x}" = "$2" ]; then echo "  ok   $1=$v"; else echo "  FAIL $1=${v:-?} (expected $2)"; rc=1; fi; }
	# 15 positive + 4 accepted in the window phase + 1 post-garbage control
	# = 20 round trips (20 ESP in + 20 ESP out, 40 tx).  ESP in beyond
	# those: 1198 replayed + 1336 (distance 64) -> replay (authenticated,
	# then refused by our window); 1019 (far too old) + truncated ESP ->
	# ipsec_reject (rte_ipsec prepare); bit-flip + tampered seq ->
	# crypto_fail; unknown SPI -> no_sa_in; off-selector -> inner_sel.
	# The cleartext ICMP is the one non-ESP frame (clear_outer).
	eq rx 49; eq tx 40; eq esp 48; eq ike 0
	eq replay 2; eq ipsec_reject 2; eq crypto_fail 2; eq no_sa_in 1
	eq inner_sel 1; eq clear_outer 1
	for z in malformed no_sa_out policy_discard crypto_enq crypto_stuck nomem no_nexthop esp_on_inner tx_full spd_fail; do eq $z 0; done
	eq drop 9
fi
kill -0 $FPID 2>/dev/null || { echo "  FAIL forwarder crashed"; cat "$D/fwd.out"; rc=1; }
[ $rc = 0 ] && echo "PASS ($BACKEND): ESP tunnel interoperates with an independent implementation" ||
	echo "FAILED (logs in $D)"
exit $rc

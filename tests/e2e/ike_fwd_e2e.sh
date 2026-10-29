#!/bin/bash
# M1 exit gate: two complete stacks -- racoon2 iked+spmd (built with
# --with-km-backend=r2dp) driving a DPDK r2dp-fwd each -- negotiate IKEv2 across
# a veth, and a kernel host behind each gateway pings the other through the
# resulting ESP tunnel.  IKE reaches iked only via the forwarders' exception
# path (net_tap); the only dataplane between the gateways is r2dp-fwd.
#
#   hostA 10.1.0.2 -- [vara|fwd A|vab] ==black== [vba|fwd B|varb] -- hostB 10.2.0.2
#                       tunnel endpoint 192.0.2.1          192.0.2.2
#
#   ike_fwd_e2e.sh <racoon2-prefix> <r2dp-fwd>           (root, iproute2, iputils-ping)
#
#   env: FLOOD_COUNT=N   after the basic checks, ping-flood hostA->hostB with N packets (50 ms apart)
#        SA_BYTES=B      give the child SAs a hard byte lifetime of B (iked derives the soft limit);
#                        iked has no byte timer, so a rekey here can only come from the forwarder's
#                        EXPIRE event -- the flood must then survive several rekeys with zero loss
#        ESN=1           negotiate extended sequence numbers (ext_sequence on)
#        ALG=cbc         use AES-128-CBC + HMAC-SHA2-256 instead of AES-GCM for the child SAs
#        NATT=1          force NAT traversal (nat_traversal force): IKE floats to UDP/4500 and ESP is
#                        UDP-encapsulated, so one port carries both and the forwarder must demux them
set -u
PREFIX="${1:?racoon2 install prefix}"; FWD="${2:?path to r2dp-fwd}"
SBIN="$PREFIX/sbin"; D=/tmp/r2dp-ikefwd
NSA=r2xa; NSB=r2xb; NSHA=r2ha; NSHB=r2hb
fail() { echo "FAIL: $*"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
command -v ip >/dev/null && command -v ping >/dev/null || { echo "SKIP: needs iproute2 + ping"; exit 77; }
[ -x "$SBIN/iked" ] && [ -x "$SBIN/spmd" ] && [ -x "$SBIN/ikedctl" ] && [ -x "$FWD" ] || fail "missing binaries"

cleanup() {
	pkill -TERM -x r2dp-fwd 2>/dev/null; pkill -9 -x iked 2>/dev/null; pkill -9 -x spmd 2>/dev/null; sleep 0.4
	pkill -9 -x r2dp-fwd 2>/dev/null
	for n in $NSA $NSB $NSHA $NSHB; do ip netns del $n 2>/dev/null; done
}
trap cleanup EXIT
cleanup; rm -rf "$D" /var/run/dpdk/r2xa /var/run/dpdk/r2xb; mkdir -p "$D/psk" "$D/ra" "$D/rb"
cp "$PREFIX/etc/racoon2/spmd.pwd" "$D/spmd.pwd"; chmod 600 "$D/spmd.pwd"
printf 'r2dp-ikefwd-secret' > "$D/psk/k.psk"; chmod 600 "$D/psk/k.psk"

for n in $NSA $NSB $NSHA $NSHB; do ip netns add $n; ip netns exec $n ip link set lo up; done
ip link add vab type veth peer name vba;   ip link set vab netns $NSA; ip link set vba netns $NSB
ip link add vara type veth peer name vhaa; ip link set vara netns $NSA; ip link set vhaa netns $NSHA
ip link add varb type veth peer name vhbb; ip link set varb netns $NSB; ip link set vhbb netns $NSHB
for x in "$NSA vab" "$NSA vara" "$NSB vba" "$NSB varb" "$NSHA vhaa" "$NSHB vhbb"; do set -- $x; ip netns exec $1 ip link set $2 up; done
mac() { ip netns exec "$1" cat /sys/class/net/"$2"/address; }
M_AB=$(mac $NSA vab); M_BA=$(mac $NSB vba); M_AR=$(mac $NSA vara); M_BR=$(mac $NSB varb); M_HA=$(mac $NSHA vhaa); M_HB=$(mac $NSHB vhbb)

# plain kernel hosts, static neighbours (the red side has no ARP responder in M1)
ip netns exec $NSHA ip addr add 10.1.0.2/24 dev vhaa; ip netns exec $NSHA ip route add 10.2.0.0/24 via 10.1.0.1
ip netns exec $NSHA ip neigh replace 10.1.0.1 lladdr "$M_AR" dev vhaa nud permanent
ip netns exec $NSHB ip addr add 10.2.0.2/24 dev vhbb; ip netns exec $NSHB ip route add 10.1.0.0/24 via 10.2.0.1
ip netns exec $NSHB ip neigh replace 10.2.0.1 lladdr "$M_BR" dev vhbb nud permanent

start_fwd() { # $1=ns $2=tag $3=black-if $4=red-if $5=local $6=peer-black-mac $7=red-subnet $8=host-mac
	ip netns exec $1 "$FWD" -l 0 --no-huge -m 256 --no-pci --no-telemetry --file-prefix r2x$2 \
		--vdev=net_af_packet0,iface=$3 --vdev=net_af_packet1,iface=$4 --vdev=net_tap0,iface=r2tap0 --vdev=crypto_openssl0 \
		-- --sock "$D/fwd-$2.sock" --local $5 -v \
		--route "192.0.2.0/24,black,$6" --route "$7,red,$8" >"$D/fwd-$2.out" 2>"$D/fwd-$2.err" &
	eval "FP_$2=$!"; disown
	for _ in $(seq 100); do [ -S "$D/fwd-$2.sock" ] && break; sleep 0.1; done
	[ -S "$D/fwd-$2.sock" ] || { cat "$D/fwd-$2.err"; fail "forwarder $2 did not start"; }
	for _ in $(seq 50); do ip netns exec $1 ip link show r2tap0 >/dev/null 2>&1 && break; sleep 0.1; done
	ip netns exec $1 ip addr add $5/24 dev r2tap0 || fail "no exception-path interface in $1"
	ip netns exec $1 ip link set r2tap0 up
}
start_fwd $NSA a vab vara 192.0.2.1 "$M_BA" 10.1.0.0/24 "$M_HA"
start_fwd $NSB b vba varb 192.0.2.2 "$M_AB" 10.2.0.0/24 "$M_HB"
grep -q "exception path enabled" "$D/fwd-a.err" || fail "exception path not enabled"

echo "== exception path: kernel-to-kernel ARP + ICMP through both forwarders' TAPs"
ip netns exec $NSA ping -c 3 -W 2 192.0.2.2 >"$D/ping-gw.out" 2>&1 || { cat "$D/ping-gw.out"; fail "gateways cannot reach each other over the exception path"; }
echo "  ok   192.0.2.1 <-> 192.0.2.2 ($(grep -o '[0-9]* received' "$D/ping-gw.out"))"

if [ "${ALG:-gcm}" = cbc ]; then ALG_LINES='esp_enc_alg { aes128_cbc; }; esp_auth_alg { hmac_sha2_256; }'
else ALG_LINES='esp_enc_alg { aes_gcm; }; esp_auth_alg { non_auth; }'; fi
conf() { # $1=file $2=my_ip $3=peer_ip $4=spmif $5=my_id $6=peer_id $7=passive $8=my_net $9=peer_net
cat > "$1" <<CONF
interface {
	ike { "$2"; };
	spmd { unix "$4"; };
	spmd_password "$D/spmd.pwd";
};
resolver { resolver off; };
remote e2e_remote {
	acceptable_kmp { ikev2; };
	ikev2 {
		$7
		${NATT:+nat_traversal force;}
		my_id fqdn "$5";
		peers_id fqdn "$6";
		peers_ipaddr "$3" port 500;
		kmp_enc_alg { aes256_cbc; aes128_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; modp2048; };
		kmp_auth_method { psk; };
		pre_shared_key "$D/psk/k.psk";
	};
	selector_index sel_in;
};
selector sel_out { direction outbound; src "$8"; dst "$9"; policy_index pol; };
selector sel_in  { direction inbound;  dst "$8"; src "$9"; policy_index pol; };
policy pol {
	action auto_ipsec;
	remote_index e2e_remote;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "$3";
	my_sa_ipaddr "$2";
};
ipsec ipsec_e { ipsec_sa_lifetime_time 3000 sec; ${SA_BYTES:+ipsec_sa_lifetime_byte $SA_BYTES bytes;} ${ESN:+ext_sequence on;} sa_index esp_e; };
sa esp_e { sa_protocol esp; ${ALG_LINES}; };
CONF
}
conf "$D/a.conf" 192.0.2.1 192.0.2.2 "$D/spmif-a" a.example b.example "" 10.1.0.0/24 10.2.0.0/24
conf "$D/b.conf" 192.0.2.2 192.0.2.1 "$D/spmif-b" b.example a.example "passive on;" 10.2.0.0/24 10.1.0.0/24

start_ike() { # $1=ns $2=tag
	ip netns exec $1 env R2DP_SOCK="$D/fwd-$2.sock" R2DP_ROLE=spmd "$SBIN/spmd" -F -f "$D/$2.conf" >"$D/spmd-$2.log" 2>&1 & disown
	for _ in $(seq 50); do [ -S "$D/spmif-$2" ] && break; sleep 0.2; done
	[ -S "$D/spmif-$2" ] || { tail -5 "$D/spmd-$2.log"; fail "spmd-$2 did not start"; }
	ip netns exec $1 env R2DP_SOCK="$D/fwd-$2.sock" R2DP_ROLE=iked RACOON2_ADMIN_SOCK="$D/iked.sock-$2" \
		RACOON2_RESUME_DIR="$D/r$2" "$SBIN/iked" -F -f "$D/$2.conf" -D 0x0001 -l "$D/iked-$2.log" >"$D/iked-$2.out" 2>&1 & disown
}
start_ike $NSB b; start_ike $NSA a
sleep 2
echo "== IKEv2: initiator a.example -> b.example (IKE packets cross both exception paths)"
ip netns exec $NSA "$SBIN/ikedctl" -s "$D/iked.sock-a" establish-sa isakmp inet 192.0.2.1 192.0.2.2 sel_out 2>&1 | head -2

ok=0
for s in $(seq 40); do
	na=$(grep -c "installed" "$D/fwd-a.err"); nb=$(grep -c "installed" "$D/fwd-b.err")
	[ "${na:-0}" -ge 2 ] && [ "${nb:-0}" -ge 2 ] && { ok=1; break; }
	sleep 1
done
echo "  forwarder A: $(grep -E 'SA (in|out) spi' "$D/fwd-a.err" | sed 's/^fwd: //' | tr '\n' ';')"
echo "  forwarder B: $(grep -E 'SA (in|out) spi' "$D/fwd-b.err" | sed 's/^fwd: //' | tr '\n' ';')"
[ $ok = 1 ] || { echo "-- iked-a --"; tail -8 "$D/iked-a.log"; echo "-- iked-b --"; tail -8 "$D/iked-b.log"; fail "IKE did not install SAs into both forwarders in ${s}s"; }

rc=0
if [ "${ALG:-gcm}" = cbc ]; then
	for side in a b; do   # IANA ids: encr 12 = AES-CBC, integ 12 = HMAC-SHA2-256-128
		n=$(grep -c "SA_\(ADD\|UPDATE\).*enc=12 integ=12" "$D/fwd-$side.err")
		[ "${n:-0}" -ge 2 ] && echo "  ok   forwarder $side received AES-CBC + HMAC-SHA2-256 SAs ($n installs)" || { echo "  FAIL forwarder $side never got a CBC+HMAC SA"; rc=1; }
	done
fi
if [ -n "${NATT:-}" ]; then
	for side in a b; do
		n=$(grep -c "SA_\(ADD\|UPDATE\).*natt=1/4500" "$D/fwd-$side.err")
		[ "${n:-0}" -ge 2 ] && echo "  ok   forwarder $side received UDP-encapsulated SAs ($n installs)" || { echo "  FAIL forwarder $side never got a NAT-T SA: NAT-T was not negotiated"; rc=1; }
	done
fi
if [ -n "${ESN:-}" ]; then
	for side in a b; do
		n=$(grep -c "SA_\(ADD\|UPDATE\).*esn=1" "$D/fwd-$side.err")
		[ "${n:-0}" -ge 2 ] && echo "  ok   forwarder $side received ESN-enabled SAs ($n installs)" || { echo "  FAIL forwarder $side never got an ESN SA: ESN was not negotiated"; rc=1; }
	done
fi
echo "== dataplane: hostA <-> hostB through the IKE-negotiated tunnel (decrypt/encrypt keys must agree)"
t() { if ip netns exec "$1" ping -c "$2" -W 2 ${4:+-s $4} "$3" >"$D/ping.out" 2>&1; then echo "  ok   $5 ($(grep -o '[0-9]* received' "$D/ping.out"))"; else echo "  FAIL $5"; tail -3 "$D/ping.out"; rc=1; fi; }
t $NSHA 5 10.2.0.2 ""   "hostA -> hostB, 5 pings"
t $NSHB 5 10.1.0.2 ""   "hostB -> hostA, 5 pings"
t $NSHA 3 10.2.0.2 1200 "hostA -> hostB, 1200-byte payload"

echo "== counters"
stat() { kill -USR1 $1; sleep 0.5; grep -E "^(stats|drops):" "$2" | tail -2 | tr '\n' ' '; }
SA=$(stat $FP_a "$D/fwd-a.out"); SB=$(stat $FP_b "$D/fwd-b.out")
val() { echo "$1" | grep -o " $2=[0-9]*" | tail -1 | cut -d= -f2; }
for side in a b; do
	S=$([ $side = a ] && echo "$SA" || echo "$SB")
	eo=$(val "$S" esp_out); ei=$(val "$S" esp_in); by=$(val "$S" bypass); au=$(val "$S" auth); xi=$(val "$S" exc_in); xo=$(val "$S" exc_out)
	echo "  fwd $side: esp_out=$eo esp_in=$ei bypass=$by auth_fail=$au exc_in=$xi exc_out=$xo"
	[ "${eo:-0}" -ge 8 ] && [ "${ei:-0}" -ge 8 ] || { echo "  FAIL fwd $side did not carry the ESP traffic"; rc=1; }
	[ "${by:-1}" = 0 ] || { echo "  FAIL fwd $side forwarded protected traffic in the clear"; rc=1; }
	[ "${au:-1}" = 0 ] || { echo "  FAIL fwd $side saw ESP auth failures"; rc=1; }
	[ "${xi:-0}" -gt 0 ] && [ "${xo:-0}" -gt 0 ] || { echo "  FAIL fwd $side exception path unused"; rc=1; }
done
if [ -n "${FLOOD_COUNT:-}" ]; then
	echo "== flood: ${FLOOD_COUNT} pings (200 B payload, 50 ms apart)${SA_BYTES:+ across rekeys driven by a ${SA_BYTES}-byte lifetime}"
	ip netns exec $NSHA ping -i 0.05 -s 200 -c "$FLOOD_COUNT" -W 1 10.2.0.2 >"$D/flood.out" 2>&1
	line=$(grep "packets transmitted" "$D/flood.out"); echo "  $line"
	tx=$(echo "$line" | awk '{print $1}'); rx=$(echo "$line" | awk '{print $4}')
	if [ "${tx:-0}" = "$FLOOD_COUNT" ] && [ "${rx:-x}" = "$tx" ]; then echo "  ok   zero loss"; else echo "  FAIL lost $((${tx:-0} - ${rx:-0})) of ${tx:-?}"; rc=1; fi
	SA=$(stat $FP_a "$D/fwd-a.out"); SB=$(stat $FP_b "$D/fwd-b.out")
	for side in a b; do
		S=$([ $side = a ] && echo "$SA" || echo "$SB")
		es=$(val "$S" exp_soft); eh=$(val "$S" exp_hard); ns=$(val "$S" no_sp_sa); ex=$(val "$S" expired); au=$(val "$S" auth); by=$(val "$S" bypass)
		ins=$(grep -c "SA in spi" "$D/fwd-$side.err"); outs=$(grep -c "SA out spi" "$D/fwd-$side.err")
		echo "  fwd $side: soft_expiries=$es hard_expiries=$eh SAs installed in=$ins out=$outs  drops: no_sa=$ns expired=$ex auth=$au bypass=$by"
		[ "${ns:-1}" = 0 ] && [ "${ex:-1}" = 0 ] && [ "${au:-1}" = 0 ] && [ "${by:-1}" = 0 ] || { echo "  FAIL fwd $side dropped packets during the flood"; rc=1; }
	done
	if [ -n "${SA_BYTES:-}" ]; then
		# iked draws each side's soft threshold with independent jitter, so either end may win a given
		# rekey race: require EXPIRE events from *somewhere*, but multiple rekeys on *both* ends.
		soft_total=$(( $(val "$SA" exp_soft) + $(val "$SB" exp_soft) ))
		[ "$soft_total" -ge 1 ] && echo "  ok   forwarders reported $soft_total soft expiries in total" || { echo "  FAIL no forwarder ever reported a soft expiry"; rc=1; }
		for side in a b; do
			ins=$(grep -c "SA in spi" "$D/fwd-$side.err")
			[ "${ins:-0}" -ge 3 ] || { echo "  FAIL fwd $side saw fewer than 2 rekeys (inbound SAs installed: $ins)"; rc=1; }
		done
		n=$(cat "$D"/iked-a.log "$D"/iked-b.log | grep -c "received PFKEY_EXPIRE")
		[ "$n" -ge 1 ] && echo "  ok   iked logged $n EXPIRE event(s) from the forwarders" || { echo "  FAIL iked never received an EXPIRE event"; rc=1; }
	fi
fi
kill -0 $FP_a 2>/dev/null && kill -0 $FP_b 2>/dev/null || { echo "  FAIL a forwarder crashed"; rc=1; }
[ $rc = 0 ] && echo "PASS: iked negotiated IKEv2 through the exception path and the DPDK forwarders carry the ESP tunnel" || echo "FAILED (logs in $D)"
exit $rc

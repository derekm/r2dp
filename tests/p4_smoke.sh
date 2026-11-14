#!/bin/sh
# p4_smoke: start r2dp-fwd --dp p4 with two slices on net_null and check
# the backend refuses what it cannot enforce and keeps one outbound owner.
#   p4_smoke.sh R2DP_FWD R2DPCTL SPEC HAVE_REPLAY(0|1) SCRATCH SWX_SRC
# Defensive regression for COMMITS C6/C7, P4 review P1/P2.
FWD=$1; CTL=$2; SPEC=$3; HAVE_REPLAY=$4; SCR=$5; SWX=${R2DP_SWX_SRC:-$6}
# The start-up SWX codegen needs DPDK's internal lib/pipeline headers,
# which only build-dpdk-p4.sh installs; a stock DPDK can build P4 but
# not start it here.
if [ ! -f "$SWX/lib/pipeline/rte_swx_pipeline_internal.h" ]; then
	echo "SKIP: no SWX internal headers at $SWX (contrib/upstream/build-dpdk-p4.sh)"
	exit 77
fi
mkdir -p "$SCR" && chmod 700 "$SCR"
T=$(mktemp -d "$SCR/smoke.XXXXXX"); S=$T/p4.sock; LOG=$T/fwd.log
K=00112233445566778899aabbccddeeff00112233
fails=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fails=$((fails + 1)); }
R2DP_P4_SPEC=$SPEC R2DP_P4_SCRATCH=$T R2DP_P4_WORKERS=2 \
	timeout 60 "$FWD" --dp p4 -s "$S" --vdev=net_null0 --vdev=net_null1 \
	--vdev=crypto_openssl0,max_nb_queue_pairs=2 --no-huge --no-pci -m 512 \
	--no-shconf --file-prefix p4smoke$$ > "$LOG" 2>&1 &
pid=$!
for i in $(seq 1 40); do [ -S "$S" ] && break; sleep 0.5; done
if [ ! -S "$S" ]; then
	cat "$LOG"
	if [ -n "${R2DP_REQUIRE_DPDK:-}" ]; then echo "FAIL p4 forwarder did not start"; exit 1; fi
	echo "SKIP: p4 forwarder did not start"; kill $pid 2>/dev/null; exit 77
fi
c() { "$CTL" "$S" "$@" >/dev/null 2>&1; }
c sa-add dir=in spi=0x3001 src=203.0.113.1 dst=192.0.2.1 enc=aes-gcm-16 key=$K wsize=1 \
	&& bad "window 1 accepted (would be anti-replay off)" || ok "window 1 refused"
if c sa-add dir=in spi=0x3002 src=203.0.113.1 dst=192.0.2.1 enc=aes-gcm-16 key=$K wsize=64; then
	[ "$HAVE_REPLAY" = 1 ] && ok "window 64 installed (patched extern)" || bad "window 64 accepted without a replay-capable extern"
else
	[ "$HAVE_REPLAY" = 1 ] && bad "window 64 refused on a replay-capable extern" || ok "window 64 refused (stock extern)"
fi
c sa-add dir=in spi=0x3003 src=203.0.113.1 dst=192.0.2.1 enc=aes-gcm-16 key=$K wsize=0 \
	&& ok "anti-replay-off SA installed" || bad "wsize=0 SA refused"
c sa-add dir=out spi=0x2001 src=192.0.2.1 dst=203.0.113.1 enc=aes-gcm-16 key=$K \
	&& ok "outbound SA installed" || bad "outbound SA refused"
c sp-add dir=out action=bypass src=10.0.0.1/32 dst=10.0.1.1/32 proto=udp dport=500 \
	&& bad "port-qualified BYPASS accepted (widened to all ports)" || ok "port-qualified OUT BYPASS refused"
c sp-add dir=in action=bypass src=10.0.1.1/32 dst=10.0.0.1/32 proto=udp dport=500 \
	&& bad "port-qualified IN BYPASS accepted" || ok "port-qualified IN BYPASS refused"
c sp-add dir=out action=protect src=10.0.0.0/24 dst=10.0.1.0/24 tsrc=192.0.2.1 tdst=203.0.113.1 \
	&& ok "OUT PROTECT installed" || bad "OUT PROTECT refused"
sleep 1
grep -q "slice 1 is not the outbound owner: PROTECT -> DISCARD" "$LOG" \
	&& ok "only slice 0 encrypts for the SA" || bad "slice 1 bound to the outbound SA"
kill $pid 2>/dev/null; wait $pid 2>/dev/null
[ $fails = 0 ] || { echo "--- forwarder log"; tail -40 "$LOG"; }
rm -rf "$T"
[ $fails = 0 ] && echo "p4_smoke: OK" || { echo "p4_smoke: $fails failures"; exit 1; }

#!/bin/bash
# End-to-end forwarder throughput: real packet I/O through two r2dp-fwd
# instances over DPDK memif links, driven by bench/e2e_tgen.
#
#   e2e_tgen port0 ==memif== [inner] r2dp A [outer] ==memif== [outer] r2dp B [inner] ==memif== e2e_tgen port1
#         plaintext              encrypt          ESP             decrypt           plaintext, validated
#
# Usage: bench/e2e_bench.sh BUILD_DIR
#   W=1|2|4 workers per forwarder (no dispatcher lcore).  Both forwarders
#   get W.  Memif has no queues= argument; both sides configure W queue
#   pairs.  Tunnel t is owned by worker t % W (least-loaded install
#   order) and the generator transmits it on TX queue t % W, so the
#   owner receives it in place.
#   NTUN=1..16384 tunnels (each its own peer address 203.0.113.1 + t, so
#   they spread over
#   workers), NATT=1 ESP-in-UDP SAs, SIZES=64,512,1400 (Ethernet
#   frame bytes), SECS=2 per trial, LOSS=0.001 (no-loss threshold)
#   CPU placement: TG_CPUS="0,1" (tx,rx) A_CPUS="2,3" B_CPUS="4,5"
#   (one CPU per worker, no dispatcher) MAIN_CPUS="6" (control, not a
#   data-path CPU)
#   LOOP=1: no forwarders -- the generator's two ports wired to each other,
#   the generator + memif ceiling.
# Prints one JSON line per size (generator results, plus each forwarder's
# counter deltas over that size: a_rx a_tx a_txfull ... ); needs no root
# or hugepages.
set -u
B=${1:?build dir}
FWD=$B/fwd/r2dp-fwd; CTL=$B/r2dpctl; TG=$B/bench/e2e_tgen
W=${W:-1}; B_W=$W; NTUN=${NTUN:-1}; NATT=${NATT:-0}; SIZES=${SIZES:-64,512,1400}
SECS=${SECS:-2}; LOSS=${LOSS:-0.001}
TG_CPUS=${TG_CPUS:-0,1}; MAIN_CPUS=${MAIN_CPUS:-6-7}
A_CPUS=${A_CPUS:-2}; B_CPUS=${B_CPUS:-3}
D=$(mktemp -d "${TMPDIR:-/tmp}/r2dp-e2eb.XXXXXX")
PIDS=
cleanup() { for p in $PIDS; do kill -TERM $p 2>/dev/null; done; wait 2>/dev/null; rm -rf "$D"; }
trap cleanup EXIT
[ -n "${KEEP:-}" ] && trap "for p in \$PIDS; do kill -TERM \$p 2>/dev/null; done; wait; echo logs in \$D" EXIT

lcores() {   # $1 = comma list of CPUs, one per worker
	local l="0@($MAIN_CPUS)" i=1
	for c in ${1//,/ }; do l="$l,$i@$c"; i=$((i + 1)); done
	echo "$l"
}
for x in "$W:$A_CPUS" "$B_W:$B_CPUS"; do
	w=${x%%:*}; need=$w
	[ "$(echo "${x#*:}" | tr ',' ' ' | wc -w)" -ge $need ] || { echo "need $need CPUs for $w workers (A_CPUS/B_CPUS)"; exit 2; }
done
# PMD=aesni_mb|openssl (crypto PMD), HUGE=1: use hugepages (default --no-huge)
PMD=${PMD:-aesni_mb}; MEM="--no-huge -m 1024"; [ "${HUGE:-0}" = 1 ] && MEM="-m 1024"
EAL="$MEM --no-pci --no-telemetry --vdev=crypto_${PMD}0 --log-level=lib.*:error"
if [ "${LOOP:-0}" != 1 ]; then
"$FWD" -s "$D/a.sock" -n "$W" --lcores "$(lcores "$A_CPUS")" $EAL --file-prefix r2a$$ \
	--vdev=net_memif0,role=server,socket=$D/ab.sock \
	--vdev=net_memif1,role=server,socket=$D/ai.sock >"$D/a.out" 2>&1 &
PIDS="$PIDS $!"
# B's outer memif is a client of A's: A's socket must exist first
for _ in $(seq 100); do [ -S "$D/ab.sock" ] && [ -S "$D/a.sock" ] && break; sleep 0.1; done
"$FWD" -s "$D/b.sock" -n "$B_W" --lcores "$(lcores "$B_CPUS")" $EAL --file-prefix r2b$$ \
	--vdev=net_memif0,role=client,socket=$D/ab.sock \
	--vdev=net_memif1,role=server,socket=$D/bi.sock >"$D/b.out" 2>&1 &
PIDS="$PIDS $!"
for s in a b; do
	for _ in $(seq 100); do [ -S "$D/$s.sock" ] && break; sleep 0.1; done
	grep -q "DPDK dataplane ready" "$D/$s.out" || { sleep 1; }
	grep -q "DPDK dataplane ready" "$D/$s.out" || { echo "forwarder $s did not come up"; cat "$D/$s.out"; exit 1; }
done
K=000102030405060708090a0b0c0d0e0f10111213
NT=""; [ "$NATT" = 1 ] && NT="natt=4500:4500"
for t in $(seq 0 $((NTUN - 1))); do
	[ $t -ge 16384 ] && { echo "NTUN <= 16384"; exit 2; }
	n=$((0xcb007101 + t)); P=$((n >> 24 & 255)).$((n >> 16 & 255)).$((n >> 8 & 255)).$((n & 255))
	S=10.$((2 + 2 * (t >> 8))).$((t & 255)).0/24; R=10.$((1 + 2 * (t >> 8))).$((t & 255)).0/24
	SPI=$(printf 0x%x $((0x2000 + t)))
	"$CTL" "$D/a.sock" sa-add dir=out spi=$SPI src=192.0.2.1 dst=$P enc=aes-gcm-16 key=$K $NT >/dev/null &&
	"$CTL" "$D/a.sock" sp-add slid=$((t + 1)) dir=out action=protect src=$S dst=$R tsrc=192.0.2.1 tdst=$P >/dev/null &&
	"$CTL" "$D/b.sock" sa-add dir=in spi=$SPI src=192.0.2.1 dst=$P enc=aes-gcm-16 key=$K $NT >/dev/null &&
	"$CTL" "$D/b.sock" sp-add slid=$((t + 1)) dir=in action=protect src=$S dst=$R tsrc=192.0.2.1 tdst=$P >/dev/null ||
	{ echo "tunnel $t setup failed"; exit 1; }
done
fi
# counters of forwarder $1 (a|b): rx tx drop tx_full
ctr() {
	local f=$D/$1.out p n
	p=$([ $1 = a ] && echo $APID || echo $BPID)
	n=$(grep -c "r2dp-fwd: drops" "$f")
	kill -USR1 $p
	for _ in $(seq 30); do [ "$(grep -c "r2dp-fwd: drops" "$f")" -gt "$n" ] && break; sleep 0.1; done
	grep -E "r2dp-fwd: (stats .*spd_fail|drops)" "$f" | tail -2 | tr '\n' ' ' |
	    sed -E 's/.*stats rx=([0-9]+) tx=([0-9]+) .*drop=([0-9]+) spd_fail.*tx_full=([0-9]+).*/\1 \2 \3 \4/'
}
APID=$(echo $PIDS | cut -d' ' -f1); BPID=$(echo $PIDS | cut -d' ' -f2)
if [ "${LOOP:-0}" = 1 ]; then
	TGV="--vdev=net_memif0,role=server,socket=$D/lp.sock --vdev=net_memif1,role=client,socket=$D/lp.sock"
else
	TGV="--vdev=net_memif0,role=client,socket=$D/ai.sock --vdev=net_memif1,role=client,socket=$D/bi.sock"
fi
TC=${TG_CPUS%%,*}; RC=${TG_CPUS##*,}
for SZ in ${SIZES//,/ }; do
	[ "${LOOP:-0}" = 1 ] || { CA0=($(ctr a)); CB0=($(ctr b)); }
	J=$("$TG" --lcores "0@$TC,1@$RC" $MEM --no-pci --no-telemetry --file-prefix r2t$$ \
		--log-level=lib.*:error $TGV -- \
		--sizes "$SZ" --tunnels "$NTUN" --secs "$SECS" --loss "$LOSS" --rxq "$(( W > B_W ? W : B_W ))" ${TG_ARGS:-} 2>"$D/tg.err" | grep "^{")
	X=""
	if [ "${LOOP:-0}" != 1 ]; then
		CA1=($(ctr a)); CB1=($(ctr b))
		X=",\"a_rx\":$((CA1[0]-CA0[0])),\"a_tx\":$((CA1[1]-CA0[1])),\"a_drop\":$((CA1[2]-CA0[2])),\"a_txfull\":$((CA1[3]-CA0[3])),\"b_rx\":$((CB1[0]-CB0[0])),\"b_tx\":$((CB1[1]-CB0[1])),\"b_drop\":$((CB1[2]-CB0[2])),\"b_txfull\":$((CB1[3]-CB0[3]))"
	fi
	echo "$J" | sed "s/^{/{\"workers\":$W,\"b_workers\":$B_W,\"natt\":$NATT,\"loop\":${LOOP:-0},/; s/}\$/$X}/"
done

#!/bin/bash
# Data-driven broad saturation benchmark for the N-initiator lab.
# Loops over lab.manifest (no hardcoded initiators).  Measures:
#  1. single-flow per-initiator (offered sweep) -- honest per-SA ceiling
#  2. aggregate when all N initiators load concurrently
#  3. forwarder per-worker spread (the whole point: N flows -> N workers)
set -u
LB="${LB:-/home/yescorp/bench}"
CFG="${CFG:-$LB/configs}"
. "$CFG/lab.manifest" 2>/dev/null || { echo "no manifest"; exit 2; }
RES="$LB/results"
mkdir -p "$RES"
DUR="${DUR:-8}"
OUTCSV="${OUTCSV:-$RES/r2dp-multi_broad.csv}"
FP=$(pgrep -af "r2mc-fresh.*r2dp-fwd" | grep -v bash | awk '{print $1}' | head -1)

# initiator index arrays from manifest
NS=(); OUT=(); INN=()
for i in $(seq 0 $((NINIT-1))); do
  eval "row=\$I$i"; IFS=: read -r idx ns ouc inc _ _ _ _ _ <<< "$row"
  NS+=($ns); OUT+=($ouc); INN+=($inc)
done

sudo ip netns exec nsB pkill -9 -f "iperf3 -s" 2>/dev/null
sleep 1
sudo ip netns exec nsB iperf3 -s -p 5400 >/dev/null 2>&1 &
sleep 1

echo "initiator,offered,delivered_mbps,loss_pct" > "$OUTCSV"

# Phase 1: each initiator alone (single-flow baseline), offered sweep 250/600M
for k in "${!NS[@]}"; do
  for off in 250M 600M; do
    out=$(sudo ip netns exec "${NS[$k]}" timeout $((DUR+2)) iperf3 -c "$RESP_INNER" -p 5400 -t $DUR --udp -b "$off" 2>/dev/null | grep -a "receiver" | tail -1)
    mbps=$(echo "$out" | awk '{print $7}')
    loss=$(echo "$out" | awk '{gsub(/[()%]/,"",$NF); print $NF}')
    [ -z "$mbps" ] && { mbps=0; loss=100; }
    echo "${NS[$k]},$off,$mbps,$loss" | tee -a "$OUTCSV"
  done
done

# Phase 2: ALL initiators concurrently, oversubscribed -- aggregate + spread
echo "--- concurrent aggregate (all $NINIT initiators) ---"
sudo ip netns exec nsB pkill -9 -f "iperf3 -s" 2>/dev/null; sleep 1
sudo ip netns exec nsB iperf3 -s -p 5400 > /tmp/iserver_sum.out 2>&1 &
sleep 1
# snapshot worker esp before
sudo kill -USR1 $FP 2>/dev/null; sleep 1
grep -aoE "esp=[0-9]+" /tmp/fwd_i.log 2>/dev/null | tail -1 > /tmp/esp_before.txt
for k in "${!NS[@]}"; do
  ( sudo ip netns exec "${NS[$k]}" timeout $((DUR+2)) iperf3 -c "$RESP_INNER" -p 5400 -t $DUR --udp -b 2000M >/dev/null 2>&1 ) &
done
wait
sleep 2
echo "B-side server SUM (aggregate delivered):"
grep -aE "SUM|receiver" /tmp/iserver_sum.out | tail -3
echo "=== per-worker spread (rx/esp per worker) ==="
sudo kill -USR1 $FP 2>/dev/null; sleep 1
grep -aE "\[[0-9]\]: stats" /tmp/fwd_i.log 2>/dev/null | tail -$((NWORKERS))
sudo pkill -9 -f "iperf3 -s" 2>/dev/null

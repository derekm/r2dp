#!/bin/bash
# Manifest-driven worker-spread measurement (requires lab up + distributor fwd).
# Concurrent socat UDP floods on the SA-established port from every initiator;
# reads per-worker esp deltas over one window.  This is the proof the software
# distributor assigns flows to ALL workers (vs. the kernel tap RSS hash, which
# collapsed N flows onto ~2 workers).
set -u
LB="${LB:-/home/yescorp/bench}"
CFG="${CFG:-$LB/configs}"
. "$CFG/lab.manifest" 2>/dev/null || { echo "no manifest"; exit 2; }
FP=$(pgrep -af "r2mc-fresh.*r2dp-fwd" | grep -v bash | awk '{print $1}' | head -1)
PORT="${DATA_PORT:-6400}"
DUR="${DUR:-6}"
[ -n "$FP" ] || { echo "no forwarder"; exit 2; }
echo "fwd=$FP  initiators=$NINIT  workers=$NWORKERS"
sudo pkill -9 -f "iperf3|socat" 2>/dev/null
sleep 1
sudo ip netns exec nsB socat -u UDP4-RECV:$PORT- - >/dev/null 2>&1 &
sleep 1
snap() { sudo kill -USR1 $FP 2>/dev/null; sleep 1; sudo grep -aE "^r2dp-fwd\[[0-9]+\]: stats" /tmp/fwd_i.log | tail -$((NWORKERS)) | sort -t'[' -k2 -n | grep -aoE "esp=[0-9]+"; }
B=$(snap)
for i in $(seq 0 $((NINIT-1))); do
  inner="192.0.2.$((2+i))"
  ns="nsI$i"
  sudo ip netns exec "$ns" timeout $((DUR+3)) python3 -c "
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); p=bytes(1400)
end=time.time()+$DUR
while time.time()<end: s.sendto(p,('$RESP_INNER',$PORT))" >/dev/null 2>&1 &
done
sleep $((DUR+3))
A=$(snap)
echo "=== per-worker esp delta over ${DUR}s concurrent window ==="
mapfile -t bb <<< "$B"; mapfile -t aa <<< "$A"
total=0
for k in $(seq 0 $((NWORKERS-1))); do
  d=$(( ${aa[$k]#esp=} - ${bb[$k]#esp=} ))
  echo "  worker[$((k+2))]: +$d esp"
  total=$((total+d))
done
echo "TOTAL +$total esp over ${DUR}s = $(awk "BEGIN{printf \"%.1fK\", $total/$DUR/1000}") Kpps aggregate"
sudo pkill -9 -f "iperf3|socat" 2>/dev/null
echo done

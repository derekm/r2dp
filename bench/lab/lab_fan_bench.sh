#!/bin/bash
# A (fan-out) benchmark: concurrent socat UDP flood on the SA data port from
# all 4 initiators; B listens on the fan veths (vfi0a..3a).  Gauge = forwarder
# per-worker esp deltas + aggregate.  Compare to ~1.5G single-tap ceiling.
FP=$(pgrep -af "r2mc-fresh.*r2dp-fwd" | grep -v bash | awk '{print $1}' | head -1)
N="${NINIT:-4}"
PORT="${DATA_PORT:-6400}"
DUR="${DUR:-6}"
echo "fwd=$FP  initiators=$N  dur=${DUR}s"
sudo pkill -9 -f "iperf3|socat" 2>/dev/null
sleep 1
# B: socat UDP sink on 192.0.2.1:PORT (arrives via br0 from any fan tap)
sudo ip netns exec nsB socat -u UDP4-RECV:$PORT- - >/dev/null 2>&1 &
sleep 1
snap() { sudo kill -USR1 $FP 2>/dev/null; sleep 1; sudo grep -aE "^r2dp-fwd\[[0-9]+\]: stats" /tmp/fwd_fan.log | tail -$((N)) | sort -t'[' -k2 -n | grep -aoE "esp=[0-9]+"; }
B=$(snap)
echo "flooding all $N initiators to 192.0.2.1:$PORT..."
for i in $(seq 0 $((N-1))); do
  sudo ip netns exec nsI$i timeout $((DUR+3)) python3 -c "
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); p=bytes(1400)
end=time.time()+$DUR
while time.time()<end: s.sendto(p,('192.0.2.1',$PORT))" >/dev/null 2>&1 &
done
sleep $((DUR+3))
A=$(snap)
echo "=== per-worker esp delta over ${DUR}s (fan-out inner taps) ==="
mapfile -t bb <<< "$B"; mapfile -t aa <<< "$A"
total=0
for k in $(seq 0 $((N-1))); do
  d=$(( ${aa[$k]#esp=} - ${bb[$k]#esp=} ))
  echo "  worker[$((k+2))]: +$d esp"
  total=$((total+d))
done
pps=$((total/${DUR}))
gbs=$(awk "BEGIN{printf \"%.2f\", $total*1400*8/$DUR/1e9}")
echo "TOTAL +$total esp / ${DUR}s = ${pps} Kpps  (est ${gbs} Gbps @1400B)"
echo "(single-tap ceiling was ~1.5 Gbps / ~1.1 Gbps measured)"
sudo pkill -9 -f "iperf3|socat" 2>/dev/null
echo done

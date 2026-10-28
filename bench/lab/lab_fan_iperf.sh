#!/bin/bash
# A benchmark via iperf3 UDP (reliable ESP carrier; establishes its own flow).
FP=$(pgrep -af "r2mc-fresh.*r2dp-fwd" | grep -v bash | awk '{print $1}' | head -1)
N="${NINIT:-4}"
DUR="${DUR:-6}"
echo "fwd=$FP  initiators=$N  dur=${DUR}s"
sudo pkill -9 -f "iperf3|socat" 2>/dev/null
sleep 1
sudo ip netns exec nsB iperf3 -s -p 5400 >/tmp/fansrv.out 2>&1 &
sleep 2
echo "=== single initiator0 UDP connect test ==="
sudo ip netns exec nsI0 timeout 10 iperf3 -c 192.0.2.1 -p 5400 -t 4 --udp -b 300M 2>&1 | grep -aE "SUM|receiver|error" | tail -3
echo "=== concurrent all N (5s each, oversubscribed) ==="
for i in $(seq 0 $((N-1))); do
  sudo ip netns exec nsI$i timeout $((DUR+4)) iperf3 -c 192.0.2.1 -p 5400 -t $DUR --udp -b 2000M >/tmp/fan$i.out 2>&1 &
done
sleep $((DUR+6))
echo "=== per-initiator delivered ==="
sum=0
for i in $(seq 0 $((N-1))); do
  m=$(grep -a "receiver" /tmp/fan$i.out | tail -1 | awk '{print $7}')
  [ -z "$m" ] && m=0
  echo "  initiator$i: ${m} Mbps"
  sum=$((sum + ${m%.*}))
done
echo "AGGREGATE (sum of per-client delivered): ${sum} Mbps"
echo "=== B server SUM ==="; grep -aE "SUM" /tmp/fansrv.out | tail -1 | awk '{print $7" Mbps"}'
echo "=== per-worker esp delta ==="
sudo kill -USR1 $FP 2>/dev/null; sleep 1
sudo grep -aE "^r2dp-fwd\[[0-9]+\]: stats" /tmp/fwd_fan.log | tail -$N | sort -t'[' -k2 -n | grep -aoE "esp=[0-9]+"
sudo pkill -9 -f "iperf3|socat" 2>/dev/null
echo done

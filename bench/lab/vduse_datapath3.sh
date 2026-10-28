#!/bin/bash
MB=/home/yescorp/dpdk-mb-prefix
# re-send and grep testpmd's printed port stats from its log
echo "clear port stats all" > /tmp/vduse_run/cmd.fifo 2>/dev/null; sleep 1
sudo timeout 3 bash -c 'for i in $(seq 1 40000); do printf "pkt%d-%s" $i "$(head -c64 /dev/zero | tr "\0" "x")" > /dev/udp/10.99.0.2/9999 2>/dev/null; done' 2>/dev/null || true
sleep 2
echo "show port stats 0" > /tmp/vduse_run/cmd.fifo 2>/dev/null; sleep 1
echo "=== testpmd printed port stats in log ==="
sudo tail -40 /tmp/vduse_pmd.log 2>/dev/null | grep -aiE "RX-packets|TX-packets|Forwarding IO|Port 0" | cut -c1-70
echo "=== eth0 final counters ==="
sudo ip -s link show eth0 2>/dev/null | grep -A1 "TX:" | tail -1

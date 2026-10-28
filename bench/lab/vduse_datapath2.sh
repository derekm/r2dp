#!/bin/bash
# Verify VDUSE data path: eth0 (10.99.0.1/24) -> send to 10.99.0.2 on same
# link -> testpmd (peer) should RX them.
MB=/home/yescorp/dpdk-mb-prefix
sudo ip addr add 10.99.0.1/24 dev eth0 2>/dev/null
sudo ip link set eth0 up 2>/dev/null
# ensure testpmd forwarding (io)
echo "set fwd io" > /tmp/vduse_run/cmd.fifo 2>/dev/null; sleep 1
echo "start" > /tmp/vduse_run/cmd.fifo 2>/dev/null; sleep 1
echo "clear port stats all" > /tmp/vduse_run/cmd.fifo 2>/dev/null; sleep 1
echo "=== before: ping (ICMP won't ARP to a peer; use raw UDP to subnet) ==="
sudo timeout 3 bash -c 'for i in $(seq 1 30000); do printf "pkt%d-%s" $i "$(head -c64 /dev/zero | tr "\0" "x")" > /dev/udp/10.99.0.2/9999 2>/dev/null; done' 2>/dev/null || true
sleep 2
echo "show port stats 0" > /tmp/vduse_run/cmd.fifo 2>/dev/null; sleep 1
echo "=== testpmd log rx/tx ==="
sudo grep -aE "RX-packets|TX-packets|RX-missed" /tmp/vduse_pmd.log | tail -6 | cut -c1-60
echo "=== eth0 counters (tx should climb; rx is what testpmd loops back) ==="
sudo ip -s link show eth0 2>/dev/null | grep -A1 "TX:" | head -2

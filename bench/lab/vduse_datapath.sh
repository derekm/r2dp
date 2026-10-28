#!/bin/bash
# Verify the VDUSE data path: send packets on kernel eth0, see testpmd RX.
MB=/home/yescorp/dpdk-mb-prefix
TP=$(pgrep -f "dpdk-testpmd" | head -1)
echo "testpmd=$TP"
# toggle promisc/forward so testpmd counts what eth0 delivers
echo "set fwd io" > /tmp/vduse_run/cmd.fifo 2>/dev/null
sleep 1
echo "start" > /tmp/vduse_run/cmd.fifo 2>/dev/null
sleep 1
# baseline rx counter from testpmd
sudo env LD_LIBRARY_PATH=$MB/lib64 $MB/bin/dpdk-proc-info -- --help >/dev/null 2>&1
# simpler: flood eth0 and watch testpmd "show port stats" via FIFO
echo "show port stats 0" > /tmp/vduse_run/cmd.fifo 2>/dev/null
sleep 1
# send a burst of UDP on eth0
sudo ip addr add 10.99.0.1/24 dev eth0 2>/dev/null || true
sudo timeout 3 bash -c 'for i in $(seq 1 20000); do printf "x%.900d" $i > /dev/udp/169.254.0.1/9999 2>/dev/null; done' 2>/dev/null || true
sleep 2
echo "show port stats 0" > /tmp/vduse_run/cmd.fifo 2>/dev/null
sleep 1
echo "=== testpmd log (RX counters) ==="
sudo grep -aE "RX-packets|TX-packets|Port 0" /tmp/vduse_pmd.log | tail -8 | cut -c1-80

#!/bin/bash
# VDUSE persistent bring-up v2: testpmd reads from a FIFO; we start the port
# after vdpa add; keep everything alive.
MB=/home/yescorp/dpdk-mb-prefix
DIR=/tmp/vduse_run
sudo rm -rf $DIR /var/run/dpdk/rte /var/run/vduse
sudo mkdir -p $DIR
sudo rm -f $DIR/cmd.fifo
sudo mkfifo $DIR/cmd.fifo
sudo chmod 666 $DIR/cmd.fifo
# open FIFO rdwr so testpmd never sees EOF
exec 8<>$DIR/cmd.fifo
sudo vdpa dev del r2dp 2>/dev/null
sudo pkill -9 -f "dpdk-testpmd" 2>/dev/null
sleep 1
# start testpmd with FIFO as stdin, keep running
setsid sudo bash -c "exec $MB/bin/dpdk-testpmd -l 0-3 --no-pci --file-prefix=vd --vdev=net_vhost0,iface=/dev/vduse/r2dp,queues=1 -- -i --rxd=1024 --txd=1024 < $DIR/cmd.fifo" > /tmp/vduse_pmd.log 2>&1 &
TP=$!
sleep 6
echo "=== testpmd started (pid $TP) ==="
sudo vdpa dev add name r2dp mgmtdev vduse 2>&1 | head -2
sleep 3
echo "start" > $DIR/cmd.fifo
sleep 3
echo "=== vdpa show ==="; sudo vdpa dev show 2>&1 | head
echo "=== kernel netdev ==="; sudo ip link show 2>/dev/null | grep -iE "eth0|r2dp|vduse" | head
echo "=== testpmd log ==="; sudo grep -aiE "vduse|link state|start|error|net_vhost" /tmp/vduse_pmd.log | tail -8 | cut -c1-90
echo "testpmd alive: $(pgrep -f dpdk-testpmd | head -1)"

#!/bin/bash
# Robust persistent VDUSE: FIFO-driven testpmd (port starts on demand).
MB=/home/yescorp/dpdk-mb-prefix
sudo modprobe vduse virtio_vdpa vhost_vdpa 2>/dev/null
sudo vdpa dev del r2dp 2>/dev/null
sudo pkill -9 -f "dpdk-testpmd" 2>/dev/null
sudo rm -rf /var/run/dpdk/rte /var/run/vduse /tmp/tp_cmd.fifo
sleep 1
mkfifo /tmp/tp_cmd.fifo; exec 9<>/tmp/tp_cmd.fifo   # keep it open (no EOF)
sudo env LD_LIBRARY_PATH=$MB/lib64 RTE_DRIVER_DIR=$MB/lib64/dpdk/pmds-26.0 \
  nohup bash -c "$MB/bin/dpdk-testpmd -l 0-3 --no-pci --file-prefix=vd \
  --vdev=net_vhost0,iface=/dev/vduse/r2dp,queues=1 -- -i --rxd=1024 --txd=1024 < /tmp/tp_cmd.fifo" \
  > /tmp/vduse_pmd.log 2>&1 &
TP=$!
sleep 5
echo "=== register kernel vdpa ==="
sudo vdpa dev add name r2dp mgmtdev vduse 2>&1 | head -2
sleep 3
echo "=== start the testpmd port (feed start) ==="
echo "start" > /tmp/tp_cmd.fifo
sleep 3
echo "=== vdpa show ==="; sudo vdpa dev show 2>&1 | head
echo "=== kernel netdev ==="; sudo ip link show 2>/dev/null | grep -iE "eth0|r2dp" | head
echo "=== testpmd log ==="; grep -aiE "vduse|link state|start|error" /tmp/vduse_pmd.log | tail -8 | cut -c1-90
echo "TP=$TP (alive: $(kill -0 $TP 2>/dev/null && echo yes || echo no))"

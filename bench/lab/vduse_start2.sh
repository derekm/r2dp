#!/bin/bash
# Reliable testpmd start: pipe "start\nquit" into stdin so the vhost/VDUSE
# port comes up, then register the kernel vdpa device.
MB=/home/yescorp/dpdk-mb-prefix
sudo modprobe vduse 2>/dev/null
sudo vdpa dev del r2dp 2>/dev/null
sudo pkill -9 -f "dpdk-testpmd" 2>/dev/null
sudo rm -rf /var/run/dpdk/rte /var/run/vduse
sleep 1
# NOTE: vhost for VDUSE needs the device file to exist before vdpa add.
# Run testpmd to create the config, but start needs the kernel side too.
# Instead: create VDUSE device via DPDK, then vdpa add, then testpmd start.
sudo env LD_LIBRARY_PATH=$MB/lib64 RTE_DRIVER_DIR=$MB/lib64/dpdk/pmds-26.0 \
  nohup $MB/bin/dpdk-testpmd -l 0-3 --no-pci --file-prefix=vd \
  --vdev=net_vhost0,iface=/dev/vduse/r2dp,queues=1 -- -i --rxd=1024 --txd=1024 > /tmp/vduse_pmd.log 2>&1 &
sleep 5
echo "=== pre-start /dev/vduse ==="; ls /dev/vduse/ 2>/dev/null
# vdpa add may need to happen before testpmd's device start for VDUSE
echo "=== vdpa add (before start) ==="; sudo vdpa dev add name r2dp mgmtdev vduse 2>&1 | head -3
sleep 2
echo "=== /dev/vduse after vdpa add ==="; ls -la /dev/vduse/ 2>/dev/null | head
echo "=== vdpa show ==="; sudo vdpa dev show 2>&1 | head
echo "=== kernel netdev ==="; sudo ip link show 2>/dev/null | grep -iE "r2dp" | head
echo "=== testpmd log ==="; grep -aiE "vduse|vhost|link|start|ready|error" /tmp/vduse_pmd.log | tail -10 | cut -c1-100

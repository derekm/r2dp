#!/bin/bash
# Drive testpmd with piped commands so the vhost/VDUSE port STARTS and
# creates /dev/vduse/r2dp, then register the kernel vdpa device.
MB=/home/yescorp/dpdk-mb-prefix
sudo modprobe vduse virtio_vdpa vhost_vdpa 2>/dev/null
sudo vdpa dev del r2dp 2>/dev/null
sudo pkill -9 -f "dpdk-testpmd" 2>/dev/null
sudo rm -rf /var/run/dpdk/rte /var/run/vduse
sleep 1
# pipe commands into testpmd: start the port, keep it running (no quit for 30s)
{ echo "start"; sleep 30; echo "quit"; } | \
sudo env LD_LIBRARY_PATH=$MB/lib64 RTE_DRIVER_DIR=$MB/lib64/dpdk/pmds-26.0 \
  timeout 35 $MB/bin/dpdk-testpmd -l 0-3 --no-pci --file-prefix=vd \
  --vdev=net_vhost0,iface=/dev/vduse/r2dp,queues=1 -- -i --rxd=1024 --txd=1024 > /tmp/vduse_pmd.log 2>&1 &
TP=$!
sleep 6
echo "=== /dev/vduse (device created after port start?) ==="
ls -la /dev/vduse/ 2>/dev/null
echo "=== vdpa add r2dp ==="
sudo vdpa dev add name r2dp mgmtdev vduse 2>&1 | head -2
echo "=== vdpa show ==="
sudo vdpa dev show 2>&1 | head -4
echo "=== netdev appeared? ==="
sudo ip link show 2>/dev/null | grep -iE "r2dp" | head
echo "=== testpmd log ==="
grep -aiE "vduse|vhost|link|start|ready|error|create" /tmp/vduse_pmd.log | tail -12 | cut -c1-100
wait $TP 2>/dev/null
echo done

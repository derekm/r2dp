#!/bin/bash
# Start testpmd non-interactively so the vhost/VDUSE port actually starts,
# then register the kernel vdpa device.
MB=/home/yescorp/dpdk-mb-prefix
sudo modprobe vduse 2>/dev/null
sudo vdpa dev del r2dp 2>/dev/null
sudo pkill -9 -f "dpdk-testpmd" 2>/dev/null
sudo rm -rf /var/run/dpdk/rte /var/run/vduse
sleep 1
# run testpmd non-interactive: port starts, then stays in forward loop
sudo env LD_LIBRARY_PATH=$MB/lib64 RTE_DRIVER_DIR=$MB/lib64/dpdk/pmds-26.0 \
  nohup $MB/bin/dpdk-testpmd -l 0-3 --no-pci --file-prefix=vd \
  --vdev=net_vhost0,iface=/dev/vduse/r2dp,queues=1 -- -i --rxd=1024 --txd=1024 > /tmp/vduse_pmd.log 2>&1 &
sleep 4
# drive the interactive "start" command into testpmd stdin
echo "start" | sudo bash -c 'cat > /proc/$(pgrep -f "dpdk-testpmd" | head -1)/fd/0' 2>/dev/null || true
sleep 3
echo "=== /dev/vduse now ==="
ls -la /dev/vduse/ 2>/dev/null
echo "=== vdpa add ==="
sudo vdpa dev add name r2dp mgmtdev vduse 2>&1 | head -3
echo "=== vdpa show ==="
sudo vdpa dev show 2>&1 | head
echo "=== kernel netdev ==="
sudo ip link show 2>/dev/null | grep -iE "r2dp" | head
echo "=== testpmd log tail ==="
tail -8 /tmp/vduse_pmd.log 2>/dev/null | cut -c1-100

#!/bin/bash
sudo pkill -9 -f "dpdk-testpmd" 2>/dev/null
sudo vdpa dev del r2dp 2>/dev/null
sleep 1
echo "=== loaded vdpa/vduse modules ==="
lsmod | grep -iE "vduse|vdpa|vhost" || echo "none loaded"
echo "=== kernel dmesg vduse (last 20) ==="
sudo dmesg 2>/dev/null | tail -20 | grep -iE "vduse|vdpa|virtio" || echo "no vduse lines"
echo "=== try vdpa add WITHOUT dpdk ==="
sudo vdpa dev add name r2dp mgmtdev vduse 2>&1 | head -2
sudo vdpa dev show 2>&1 | head -3
echo "=== netdev? ==="
sudo ip link show 2>/dev/null | grep -iE "r2dp|vduse" || echo "no r2dp netdev"
echo "=== dmesg after add ==="
sudo dmesg 2>/dev/null | tail -6

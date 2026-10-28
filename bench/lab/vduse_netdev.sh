#!/bin/bash
# After the vduse device is registered, bring up the kernel netdev + test link.
MB=/home/yescorp/dpdk-mb-prefix
echo "=== all kernel netdevs (looking for vduse/virtio-backed r2dp) ==="
sudo ip link show 2>/dev/null | grep -iE "r2dp|vduse|virtio" || echo "none named r2dp yet"
echo "=== full ip link brief ==="
sudo ip -br link 2>/dev/null | grep -vE "lo|veth|br|dummy|tap|vir" | head
echo "=== vdpa dev show (confirm still there) ==="
sudo vdpa dev show 2>&1 | head
echo "=== is testpmd still running? ==="
pgrep -af "dpdk-testpmd" | grep -v bash | cut -c1-40 | head -1 || echo "testpmd gone"
echo "=== testpmd pmd log tail ==="
tail -6 /tmp/vduse_pmd.log 2>/dev/null | cut -c1-90

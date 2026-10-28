#!/bin/bash
# Prove the VDUSE kernel<->DPDK mechanism with testpmd as the vhost backend.
# Steps: (re)load vduse, start testpmd with a net/vhost port at /dev/vduse/r2dp,
# then vdpa dev add + check the kernel netdev appears and carries traffic.
MB=/home/yescorp/dpdk-mb-prefix
sudo modprobe vduse 2>/dev/null
sudo modprobe virtio_vdpa 2>/dev/null
sudo modprobe vhost_vdpa 2>/dev/null
# clean prior
sudo vdpa dev del r2dp 2>/dev/null
sudo pkill -9 -f "dpdk-testpmd" 2>/dev/null
sudo rm -rf /var/run/dpdk/rte
sleep 1
# start testpmd with vhost PMD port at /dev/vduse/r2dp (server role, not client)
sudo env LD_LIBRARY_PATH=$MB/lib64 RTE_DRIVER_DIR=$MB/lib64/dpdk/pmds-26.0 \
  nohup $MB/bin/dpdk-testpmd -l 0-3 --no-pci --file-prefix=vd\
  --vdev=net_vhost0,iface=/dev/vduse/r2dp,queues=1 -- -i --rxd=1024 --txd=1024 > /tmp/vduse_pmd.log 2>&1 &
sleep 5
echo "=== testpmd vhost/vduse create log ==="
grep -aiE "vduse|vhost|creating|registered|error|fail" /tmp/vduse_pmd.log | grep -avE "^WARNING: libvirt" | head -12
echo "=== /dev/vduse devices now ==="
ls -la /dev/vduse/ 2>/dev/null
echo "=== register the vduse vdpa device ==="
sudo vdpa dev add name r2dp mgmtdev vduse 2>&1 | head -3
echo "=== vdpa dev show ==="
sudo vdpa dev show 2>&1 | head
echo "=== kernel netdev appeared? ==="
ls /sys/bus/vdpa/devices/ 2>/dev/null
sudo ip link show 2>/dev/null | grep -iE "r2dp|vduse|eno1" | head

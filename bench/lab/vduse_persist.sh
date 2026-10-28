#!/bin/bash
# Persistent VDUSE: keep testpmd forwarding alive, confirm eth0 link + rx.
MB=/home/yescorp/dpdk-mb-prefix
sudo modprobe vduse virtio_vdpa vhost_vdpa 2>/dev/null
sudo vdpa dev del r2dp 2>/dev/null
sudo pkill -9 -f "dpdk-testpmd" 2>/dev/null
sudo rm -rf /var/run/dpdk/rte /var/run/vduse
sleep 1
# keep testpmd running long; port auto-starts; no quit
sudo env LD_LIBRARY_PATH=$MB/lib64 RTE_DRIVER_DIR=$MB/lib64/dpdk/pmds-26.0 \
  nohup bash -c "{ echo start; sleep 600; } | $MB/bin/dpdk-testpmd -l 0-3 --no-pci --file-prefix=vd \
  --vdev=net_vhost0,iface=/dev/vduse/r2dp,queues=1 -- -i --rxd=1024 --txd=1024" > /tmp/vduse_pmd.log 2>&1 &
sleep 5
sudo vdpa dev add name r2dp mgmtdev vduse 2>&1 | head -2
sleep 4
echo "=== vdpa show ==="; sudo vdpa dev show 2>&1 | head
echo "=== kernel netdev ==="; sudo ip link show 2>/dev/null | grep -iE "eth0|r2dp|vduse|virtio" | head
echo "=== is testpmd alive + port linked ==="; pgrep -af dpdk-testpmd | grep -v bash | cut -c1-30 | head -1
grep -aE "link state change|start" /tmp/vduse_pmd.log | tail -3
echo "=== bring eth0 up + ping test (is there a peer?) ==="
sudo ip link set eth0 up 2>/dev/null
sudo ip addr add 10.99.0.1/24 dev eth0 2>/dev/null
sudo ip link show eth0 2>/dev/null | grep -iE "state|mtu"
echo "done (testpmd kept alive 600s)"

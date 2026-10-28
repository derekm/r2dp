#!/bin/bash
# Full forwarder-over-VDUSE bring-up.  OUTER leg = VDUSE (kernel netdev eth0
# backed by the forwarder's vhost port, zero-copy no-tap).  INNER leg = net_tap
# (B side).  A single kernel-XFRM initiator (nsA) routes ESP into eth0.
set -u
LB=/home/yescorp/bench
SRC=$LB/scripts
SESS="${R2DP_SESSION:-$LB/sessions/r2dpvd.sess}"
mkdir -p "$(dirname "$SESS")"; : > "$SESS"
N="${NINIT:-1}"
NW="${NWORKERS:-1}"
R2SRC=/home/yescorp/r2backend-fresh
FWD=/home/yescorp/r2mc-fresh/build-dpdk/fwd/r2dp-fwd
MB=/home/yescorp/dpdk-mb-prefix
FWDLD="LD_LIBRARY_PATH=$MB/lib64"
CFG=$LB/configs
L2="LD_LIBRARY_PATH=${R2SRC}/lib/.libs:/home/yescorp/r2dp-prefix/lib64"
X=/home/yescorp/xfrm-prefix
VDRUN=/tmp/vduse_run
# forwarder vhost VDUSE outer socket.nf
sudo modprobe vduse virtio_vdpa vhost_vdpa 2>/dev/null
$SRC/bench_teardown3.sh "$SESS" >/dev/null 2>&1 || true
for i in $(seq 0 $((N-1))); do sudo ip netns del nsI$i 2>/dev/null; done
sudo ip netns del nsB 2>/dev/null
sudo ip netns del nsA 2>/dev/null
sudo ip link del br0 2>/dev/null
sudo rm -rf $LB/resume-A $LB/resume-B /var/run/dpdk/rte /var/run/vduse
mkdir -p $LB/resume-A $LB/resume-B $VDRUN; chmod 777 $LB/resume-* $VDRUN
sudo vdpa dev del outer 2>/dev/null
sudo pkill -9 -f dpdk-testpmd 2>/dev/null
# FIFO to drive the forwarder's EAL? no - forwarder takes no interactive cmd.
# Instead, driver_start happens at probe; VDUSE device create needs the vhost
# port active.  net/vhost PMD in the forwarder creates /dev/vduse/<iface> at
# rte_vhost_driver_start (probe).  Launch forwarder (outer=vhost VDUSE, inner=tap)
sudo ip netns add nsB
sudo ip netns exec nsB ip link set lo up
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env $FWDLD bash -c "$FWD -n $NW -v -s /tmp/r2dp-dpdk.sock --no-pci -l 0-$((NW+2)) --vdev=crypto_aesni_mb0 --vdev=net_vhost0,iface=/dev/vduse/outer,queues=1 --vdev=net_tap0,iface=r2dp-tap-inner > /tmp/fwd_vd.log 2>&1"
# register the kernel vdpa device NOW while the forwarder retries its start
sleep 3
sudo vdpa dev add name outer mgmtdev vduse 2>&1 | head -2
sleep 8
echo "=== /dev/vduse/outer created by forwarder? ==="
ls -la /dev/vduse/ 2>/dev/null
echo "=== register kernel vdpa outer ==="
sudo vdpa dev add name outer mgmtdev vduse 2>&1 | head -2
sleep 4
echo "=== kernel netdev (eth*) ==="
sudo ip link show 2>/dev/null | grep -iE "eth[0-9]|outer|vduse" | head
echo "=== inner tap in nsB ==="
sudo ip netns exec nsB ip link set r2dp-tap-inner up 2>/dev/null
sudo ip netns exec nsB ip link set r2dp-tap-inner promisc on 2>/dev/null
sudo ip netns exec nsB ip addr add 192.0.2.1/24 dev r2dp-tap-inner 2>/dev/null
sudo ip netns exec nsB ip addr add 10.77.0.1/32 dev r2dp-tap-inner 2>/dev/null
sudo ip netns exec nsB ip route add 10.77.0.0/24 dev r2dp-tap-inner 2>/dev/null
echo "=== forwarder saw vhost VDUSE outer? ==="
grep -aE "worker on lcore|dataplane ready|inner=|outer=" /tmp/fwd_vd.log 2>/dev/null | tail -6
echo "session: $(cat $SESS | tr '\n' ' ')"

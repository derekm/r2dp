#!/bin/bash
# Robust VDUSE lab management on the shared .179 box:
#   up   - forwarder (outer = VDUSE vhost w/ UNIQUE name, inner = tap), a
#          kernel-XFRM initiator netns over the VDUSE netdev, a responder nsB
#          on the inner tap; install matching SAs.
#   down - PGID-scoped teardown + delete OUR vdpa devices.
#   stats - forwarder counters.
# UNIQUE device name sidesteps the kernel vduse state this shared box won't
# let us fully reset (module held by other tenants -> a fixed name's stale
# registration fails VDUSE_CREATE with "File exists").
set -u
LB=/home/yescorp/bench
SRC=$LB/scripts
MB=/home/yescorp/dpdk-mb-prefix
FWD=/home/yescorp/r2mc-fresh/build-dpdk/fwd/r2dp-fwd
CTL=$(find /home/yescorp/r2mc-fresh -name r2dpctl -type f | head -1)
SESS=$LB/sessions/vdmgmt.sess
LOG=/tmp/fwd_vd.log
VDNAME="r2p$(date +%s)"
VDEV_CHAR="/dev/vduse/$VDNAME"
SPI=0xbeef0001
KEY=000102030405060708090a0b0c0d0e0f10111213
OUTER_IP=192.0.2.2
HW_IP=192.0.2.1
B_INNER=10.0.2.1
HEXKEY=0x000102030405060708090a0b0c0d0e0f10111213

fwd_pid() { pgrep -af "r2mc-fresh.*r2dp-fwd" | grep -v bash | awk '{print $1}' | head -1; }

down() {
  echo "== teardown =="
  [ -f "$SESS" ] && sudo bash "$SRC/bench_teardown3.sh" "$SESS" >/dev/null 2>&1
  for p in $(pgrep -af "r2mc-fresh.*r2dp-fwd|dpdk-testpmd"|grep -v bash|awk '{print $1}'); do
    sudo kill -9 $p 2>/dev/null; done
  # delete only OUR vdpa devices (by our name prefix), never others'
  for d in $(sudo vdpa dev show 2>/dev/null | sed -n 's/^\(r2p[0-9][0-9]*\):.*/\1/p'); do
    sudo vdpa dev del "$d" 2>/dev/null; done
  sudo ip netns del nsA 2>/dev/null; sudo ip netns del nsB 2>/dev/null
  sudo ip link del br0 2>/dev/null
  sudo rm -rf /var/run/dpdk/rte /var/run/vduse /dev/vduse/$VDNAME
  echo "done"
}

ensure_ctrl() {
  sudo mkdir -p /dev/vduse
  if [ ! -e /dev/vduse/control ]; then
    sudo mknod /dev/vduse/control c 236 0 2>/dev/null
    sudo chmod 666 /dev/vduse/control
  fi
  [ -e /dev/vduse/control ] || echo "WARN: no /dev/vduse/control"
}

up() {
  down
  ensure_ctrl
  sudo modprobe vduse virtio_vdpa vhost_vdpa 2>/dev/null || true
  sleep 2
  # CRITICAL: ensure virtio_vdpa is ACTUALLY loaded -- it is what binds the
  # VDUSE device into a usable (eth) netdev.  If absent, the device registers
  # but no netdev ever materializes (the multi-session blocker: dmesg silent,
  # virtio_vdpa missing from lsmod, vdpa device 'driver' symlink dangling).
  if ! lsmod | grep -qw virtio_vdpa; then
    sudo modprobe virtio_vdpa 2>/dev/null; sleep 2
  fi
  lsmod | grep -qw virtio_vdpa && echo "virtio_vdpa: loaded" || echo "WARN: virtio_vdpa not loaded"
  sudo ip netns add nsB 2>/dev/null; sudo ip netns exec nsB ip link set lo up 2>/dev/null
  sudo ip netns add nsA 2>/dev/null; sudo ip netns exec nsA ip link set lo up 2>/dev/null
  echo "VDUSE: name=$VDNAME char=$VDEV_CHAR"
  sudo bash "$SRC/bench_spawn3.sh" "$SESS" sudo ip netns exec nsB env LD_LIBRARY_PATH=$MB/lib64 bash -c \
    "$FWD -n 1 -v -s /tmp/r2dp-dpdk.sock --no-pci -l 0-3 --vdev=crypto_aesni_mb0 --vdev=net_vhost0,iface=$VDEV_CHAR,queues=1 --vdev=net_tap1,iface=r2dp-tap-inner > $LOG 2>&1"
  V=0
  for i in $(seq 1 20); do [ -e "$VDEV_CHAR" ] && V=1 && break; sleep 1; done
  echo "char device created: $V (${i}s)"
  if [ "$V" = 1 ]; then
    sudo vdpa dev add name "$VDNAME" mgmtdev vduse 2>&1 | head -1
    sleep 4
  fi
  sudo ip netns exec nsB ip link set r2dp-tap-inner up 2>/dev/null
  sudo ip netns exec nsB ip addr add $B_INNER/24 dev r2dp-tap-inner 2>/dev/null
  echo "=== fwd vhost ==="; grep -aE "dataplane ready|ready: 1|Failed|VDUSE_SET_STATUS|Setting max" $LOG 2>/dev/null | tail -3
  echo "=== vdpa ==="; sudo vdpa dev show 2>&1 | head -3
}

config() {
  # find netdev backed by OUR vduse device name (root netns before move)
  VDEV=""
  for n in $(ls /sys/class/net 2>/dev/null); do
    [ -e "/sys/class/net/$n/device/uevent" ] && grep -qi "$VDNAME" "/sys/class/net/$n/device/uevent" 2>/dev/null && { VDEV="$n"; break; }
  done
  [ -z "$VDEV" ] && VDEV=$(ip -o link 2>/dev/null | awk -F': ' '{print $2}' | while read n; do
    grep -qi "$VDNAME" /sys/class/net/$n/device/uevent 2>/dev/null && echo "$n"; done | head -1)
  echo "VDUSE netdev: [$VDEV]"
  if [ -n "$VDEV" ]; then
    sudo ip link set "$VDEV" netns nsA 2>&1 | head -1
    sudo ip netns exec nsA ip addr add $OUTER_IP/24 dev "$VDEV" 2>/dev/null
    sudo ip netns exec nsA ip link set "$VDEV" up 2>&1 | head -1
    sudo ip netns exec nsA ip addr add 10.0.1.1/24 dev lo 2>/dev/null
    sudo ip netns exec nsA ip xfrm state add src $OUTER_IP dst $HW_IP proto esp spi ${SPI#0x} mode tunnel \
      aead 'rfc4106(gcm(aes))' $HEXKEY 128 2>&1 | head -1
    sudo ip netns exec nsA ip xfrm policy add src 10.0.1.0/24 dst 10.0.2.0/24 dir out tmpl src $OUTER_IP dst $HW_IP proto esp mode tunnel 2>&1 | head -1
  fi
  sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock sa-add dir=in spi=$SPI src=$OUTER_IP dst=$HW_IP enc=aes-gcm-16 key=$KEY 2>&1 | tail -1
  sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock sp-add dir=in action=protect src=10.0.1.0/24 dst=10.0.2.0/24 tsrc=$OUTER_IP tdst=$HW_IP 2>&1 | tail -1
}

stats() {
  FP=$(fwd_pid); [ -z "$FP" ] && { echo "no forwarder"; return; }
  sudo kill -USR1 $FP 2>/dev/null; sleep 1
  sudo grep -aE "stats rx=" $LOG | tail -1
  sudo grep -aE "drops " $LOG | tail -1 | cut -c1-170
}

case "${1:-}" in
  up) up; config; echo "== up done VDNAME=$VDNAME ==" ;;
  down) down ;;
  stats) stats ;;
  *) echo "usage: $0 {up|down|stats}" ;;
esac

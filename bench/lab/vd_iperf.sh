#!/bin/bash
# TAP-FREE end-to-end iperf3 benchmark: kernel-XFRM initiator (nsA) whose
# outer interface is the VDUSE netdev eth0 (zero-copy, no tap), forwarder
# (outer=VDUSE, inner=tap) between A and B (nsB).  Bidirectional SAs so
# iperf3's control+data round-trips.  All crypto is kernel AES-NI (A) and
# forwarder AES-GCM — no Python encrypt.
set -u
LB=/home/yescorp/bench
SRC=$LB/scripts
MB=/home/yescorp/dpdk-mb-prefix
FWD=/home/yescorp/r2mc-fresh/build-dpdk/fwd/r2dp-fwd
CTL=$(find /home/yescorp/r2mc-fresh -name r2dpctl -type f|head -1)
SESS=$LB/sessions/vdi.sess
LOG=/tmp/fwd_vdi.log
RES=$LB/results/vdi_iperf.out
VDN="r2v$(date +%s)"
VDEV_CHAR=/dev/vduse/$VDN
# SAs (both directions).  Key = 16B AES + 4B salt (20 hex bytes).
KEY=000102030405060708090a0b0c0d0e0f10111213
HEXKEY=0x000102030405060708090a0b0c0d0e0f10111213
SPI_AB=0xbeef0001   # A->B : A encrypts, forwarder decrypts
SPI_BA=0xbeef0002   # B->A : forwarder encrypts, A decrypts
OUTER_A=192.0.2.2
OUTER_B=192.0.2.1
INNER_A=10.0.1.0/24
INNER_B=10.0.2.0/24
RESP_ADDR=10.0.2.1    # B inner (iperf3 server)
INIT_ADDR=10.0.1.1    # A inner

fwd_pid() { pgrep -af "r2mc-fresh.*r2dp-fwd" | grep -v bash | awk '{print $1}' | head -1; }

NW="${NWORKERS:-1}"
teardown() {
  [ -f "$SESS" ] && sudo bash "$SRC/bench_teardown3.sh" "$SESS" >/dev/null 2>&1
  for p in $(pgrep -af "r2mc-fresh.*r2dp-fwd|dpdk-testpmd|iperf3"|grep -v bash|awk '{print $1}'); do sudo kill -9 $p 2>/dev/null; done
  for d in $(sudo vdpa dev show 2>/dev/null|sed -n 's/^\(r2[0-9a-z]*\):.*/\1/p'); do sudo vdpa dev del "$d" 2>/dev/null; done
  sudo ip netns del nsA 2>/dev/null; sudo ip netns del nsB 2>/dev/null
  sudo ip link del $OUTER_B 2>/dev/null; sudo ip link del r2dp-tap-inner 2>/dev/null
  sudo rm -rf /var/run/dpdk/rte /var/run/vduse /dev/vduse
  sudo mkdir -p /dev/vduse; sudo mknod /dev/vduse/control c 236 0 2>/dev/null; sudo chmod 666 /dev/vduse/control
}

bringup() {
  teardown
  sudo modprobe vduse virtio_vdpa vhost_vdpa 2>/dev/null || true
  sleep 1
  if ! lsmod | grep -qw virtio_vdpa; then sudo modprobe virtio_vdpa 2>/dev/null; sleep 2; fi
  lsmod | grep -qw virtio_vdpa && echo "virtio_vdpa: LOADED" || echo "WARN: virtio_vdpa MISSING"
  sudo ip netns add nsB 2>/dev/null; sudo ip netns exec nsB ip link set lo up 2>/dev/null
  sudo ip netns add nsA 2>/dev/null; sudo ip netns exec nsA ip link set lo up 2>/dev/null
  # forwarder in nsB: outer=VDUSE, inner=tap
  sudo bash "$SRC/bench_spawn3.sh" "$SESS" sudo ip netns exec nsB env LD_LIBRARY_PATH=$MB/lib64 bash -c \
    "$FWD -n $NW -v -s /tmp/r2dp-dpdk.sock --no-pci -l 0-$((NW)) --vdev=crypto_aesni_mb0 --vdev=net_vhost0,iface=$VDEV_CHAR,queues=1 --vdev=net_tap1,iface=r2dp-tap-inner > $LOG 2>&1"
  V=0; for i in $(seq 1 25); do [ -e "$VDEV_CHAR" ] && V=1 && break; sleep 1; done
  echo "VDUSE char created: $V"
  [ "$V" = 1 ] && sudo vdpa dev add name "$VDN" mgmtdev vduse 2>&1|head -2
  sleep 5
  # find the VDUSE netdev (kernel names it ethX in the root ns)
  VDEV=""
  for n in $(ls /sys/class/net 2>/dev/null); do
    [ -e /sys/class/net/$n/device/uevent ] && grep -qi "$VDN" /sys/class/net/$n/device/uevent 2>/dev/null && VDEV="$n" && break
  done
  [ -z "$VDEV" ] && VDEV=$(ip -br link 2>/dev/null | sed -n 's/^\(eth[0-9]*\).*UP.*/\1/p' | tail -1)
  echo "VDUSE netdev: [$VDEV]"
  # move into nsA (initiator), give outer IP
  if [ -n "$VDEV" ]; then
    sudo ip link set "$VDEV" netns nsA 2>&1|head -1
    sudo ip netns exec nsA ip addr add $OUTER_A/24 dev "$VDEV" 2>/dev/null
    sudo ip netns exec nsA ip link set "$VDEV" up 2>&1|head -1
    sudo ip netns exec nsA ip addr add $INIT_ADDR/24 dev lo 2>/dev/null
    echo "A outer $VDEV: $(sudo ip netns exec nsA ip -br addr show $VDEV 2>/dev/null | grep -oE '[0-9.]+/24' | head -1)"
  else
    echo "ERROR: no VDUSE netdev found"; return 1
  fi
  # B: inner tap on 10.0.2.1
  sudo ip netns exec nsB ip link set r2dp-tap-inner up 2>/dev/null
  sudo ip netns exec nsB ip addr add $RESP_ADDR/24 dev r2dp-tap-inner 2>/dev/null
  sudo ip netns exec nsB ip addr add $OUTER_B/32 dev r2dp-tap-inner 2>/dev/null
  sudo ip netns exec nsB ip route add $INNER_A dev r2dp-tap-inner 2>/dev/null
  echo "=== fwd ready ==="; grep -aE "dataplane ready|ready: 1" $LOG | tail -2
}

# Bidirectional SAs: A kernel XFRM + forwarder SAD
config() {
  # A: out (encrypt A->B) + in (decrypt B->A)
  sudo ip netns exec nsA ip xfrm state add src $OUTER_A dst $OUTER_B proto esp spi $SPI_AB mode tunnel \
    aead 'rfc4106(gcm(aes))' $HEXKEY 128 2>&1|head -1
  sudo ip netns exec nsA ip xfrm state add src $OUTER_B dst $OUTER_A proto esp spi $SPI_BA mode tunnel \
    aead 'rfc4106(gcm(aes))' $HEXKEY 128 2>&1|head -1
  sudo ip netns exec nsA ip xfrm policy add src $INNER_A dst $INNER_B dir out tmpl src $OUTER_A dst $OUTER_B proto esp mode tunnel 2>&1|head -1
  sudo ip netns exec nsA ip xfrm policy add src $INNER_B dst $INNER_A dir in  tmpl src $OUTER_B dst $OUTER_A proto esp mode tunnel 2>&1|head -1
  sudo ip netns exec nsA ip xfrm policy add src $INNER_B dst $INNER_A dir fwd tmpl src $OUTER_B dst $OUTER_A proto esp mode tunnel 2>&1|head -1
  echo "=== A XFRM ==="; sudo ip netns exec nsA ip xfrm state 2>/dev/null|grep -c esp | xargs echo "states:"; sudo ip netns exec nsA ip xfrm policy 2>/dev/null|grep -c dir | xargs echo "policy dirs:"
  # forwarder: in (decrypt A->B) + out (encrypt B->A)
  sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock sa-add dir=in spi=$SPI_AB src=$OUTER_A dst=$OUTER_B enc=aes-gcm-16 key=$KEY 2>&1|tail -1
  sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock sp-add dir=in action=protect src=$INNER_A dst=$INNER_B tsrc=$OUTER_A tdst=$OUTER_B 2>&1|tail -1
  sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock sa-add dir=out spi=$SPI_BA src=$OUTER_B dst=$OUTER_A enc=aes-gcm-16 key=$KEY 2>&1|tail -1
  sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock sp-add dir=out action=protect src=$INNER_B dst=$INNER_A tsrc=$OUTER_B tdst=$OUTER_A 2>&1|tail -1
  # A route to inner B subnet via eth0 + neighbor pin to B's inner-tap MAC.
  # Without the route, route-get on 10.0.2.1 is 'Network is unreachable';
  # without the pin, ARP reply does not traverse the forwarder so ESP never
  # transmits (clear_outer drop, esp=0).
  sudo ip netns exec nsA ip route add $INNER_B dev eth0 2>/dev/null
  INMAC=$(sudo ip netns exec nsB ip link show r2dp-tap-inner 2>/dev/null | grep -oE "([0-9a-f]{2}:){5}[0-9a-f]{2}" | head -1)
  sudo ip netns exec nsA ip neigh replace $OUTER_B dev eth0 lladdr "$INMAC" 2>/dev/null
  echo "A route: $(sudo ip netns exec nsA ip route get $RESP_ADDR 2>/dev/null | head -1)"
  echo "A neigh: $(sudo ip netns exec nsA ip neigh show dev eth0 2>/dev/null | grep $OUTER_B | head -1)"
  echo "=== fwd SAD ==="; sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock dump-sa 2>&1|tail -2
}

bench() {
  # persistent iperf3 server on B (nsB)
  sudo ip netns exec nsB pkill -f "iperf3 -s" 2>/dev/null; sleep 1
  sudo ip netns exec nsB iperf3 -s -D -p 5201 --forceflush 2>&1|tail -1
  sleep 2
  echo "=== tap-free VDUSE offered-load sweep ==="
  for R in 100 1000 2000 3000 4000; do
    O=$(sudo ip netns exec nsA timeout 24 iperf3 -B $INIT_ADDR -c $RESP_ADDR -u -b ${R}M -t 15 --forceflush 2>&1)
    sendv=$(echo "$O" | grep -m1 -oE "[0-9.]+ (G|M)bits/sec")
    recvv=$(echo "$O" | grep "receiver" | grep -oE "[0-9.]+ (G|M)bits/sec" | tail -1)
    recvl=$(echo "$O" | grep "receiver"| grep -oE "[0-9]+/[0-9]+ \([0-9]+%\)" | tail -1)
    F=$(fwdpid >/dev/null 2>&1; echo -n)
    FP=$(pgrep -af "r2mc-fresh.*r2dp-fwd"|grep -v bash|awk '{print $1}'|head -1)
    sudo kill -USR1 $FP 2>/dev/null; sleep 1
    F=$(sudo grep -a "stats rx=" $LOG | tail -1)
    echo "${R}M  send=${sendv} recv=${recvv} recvloss=${recvl}  ${F}"
  done
}

case "${1:-}" in
  up) bringup && config; echo "== up done VDN=$VDN ==" ;;
  bench) bench ;;
  down) teardown; echo "== down done ==" ;;
  *) echo "usage: $0 {up|bench|down}" ;;
esac

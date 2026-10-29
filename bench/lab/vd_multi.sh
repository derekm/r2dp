#!/bin/bash
# Multi-initiator VDUSE: forwarder exposes N net_vhost outer ports (one per
# initiator, each its own /dev/vduse device -> its own kernel netdev in its
# own netns), plus one tap inner for the responder.  Each initiator runs a
# kernel-XFRM flow to the single responder.  N workers + distributor.
#   up    - bring up forwarder + N VDUSE initiator netns + responder
#   bench - N parallel iperf3 (data-plane saturation, no iked needed)
set -u
LB=/home/yescorp/bench
SRC=$LB/scripts
MB=/home/yescorp/dpdk-mb-prefix
FWD=/home/yescorp/r2mc-fresh/build-dpdk/fwd/r2dp-fwd
CTL=$(find /home/yescorp/r2mc-fresh -name r2dpctl -type f|head -1)
SESS=$LB/sessions/vdmulti.sess
LOG=/tmp/fwd_vdmulti.log
NS="${NINIT:-4}"
NW="${NWORKERS:-$NS}"
KEY=000102030405060708090a0b0c0d0e0f10111213
HEXKEY=0x000102030405060708090a0b0c0d0e0f10111213
RESP_ADDR=10.0.2.1
declare -a VDNAME=()      # "r2m<ts>_<i>"
declare -a VDEV=()        # kernel netdev per initiator

teardown() {
  [ -f "$SESS" ] && sudo bash "$SRC/bench_teardown3.sh" "$SESS" >/dev/null 2>&1
  for p in $(pgrep -af "r2mc-fresh.*r2dp-fwd|dpdk-testpmd|iperf3|iked|spmd"|grep -v bash|awk '{print $1}'); do sudo kill -9 $p 2>/dev/null; done
  for i in $(seq 0 $((NS-1))); do sudo ip netns del vdi$i 2>/dev/null; done
  sudo ip netns del vdB 2>/dev/null
  for d in $(sudo vdpa dev show 2>/dev/null|sed -n 's/^\(r2[a-z0-9_]*\):.*/\1/p'); do sudo vdpa dev del "$d" 2>/dev/null; done
  sudo rm -rf /var/run/dpdk/rte /var/run/vduse /dev/vduse
  sudo mkdir -p /dev/vduse; sudo mknod /dev/vduse/control c 236 0 2>/dev/null; sudo chmod 666 /dev/vduse/control
}
up() {
  teardown
  sudo modprobe vduse virtio_vdpa vhost_vdpa 2>/dev/null; sleep 1
  if ! lsmod | grep -qw virtio_vdpa; then sudo modprobe virtio_vdpa 2>/dev/null; sleep 2; fi
  lsmod | grep -qw virtio_vdpa && echo "virtio_vdpa LOADED" || echo "WARN missing"
  sudo ip netns add vdB 2>/dev/null; sudo ip netns exec vdB ip link set lo up 2>/dev/null
  for i in $(seq 0 $((NS-1))); do
    sudo ip netns add vdi$i 2>/dev/null; sudo ip netns exec vdi$i ip link set lo up 2>/dev/null
    VDNAME[$i]="r2m$(date +%s)_$i"
  done
  # forwarder: N net_vhost outer (unique /dev/vduse names) + 1 tap inner
  VDEVS=""
  for i in $(seq 0 $((NS-1))); do
    VDEVS="$VDEVS --vdev=net_vhost$i,iface=/dev/vduse/${VDNAME[$i]},queues=1"
  done
  VDEVS="$VDEVS --vdev=net_tap1,iface=r2dp-tap-inner"
  echo "forwarder vdevs: $VDEVS"
  sudo bash "$SRC/bench_spawn3.sh" "$SESS" sudo ip netns exec vdB env LD_LIBRARY_PATH=$MB/lib64 bash -c \
    "$FWD -n $NW -v -s /tmp/r2dp-dpdk.sock --no-pci -l 0-$((NW+1)) $VDEVS --vdev=crypto_aesni_mb0 > $LOG 2>&1"
  # each char device -> vdpa add -> its own eth in its own netns
  for i in $(seq 0 $((NS-1))); do
    C=/dev/vduse/${VDNAME[$i]}
    V=0; for t in $(seq 1 25); do [ -e "$C" ] && V=1 && break; sleep 1; done
    echo "char $i created: $V"
    [ "$V" = 1 ] && sudo vdpa dev add name "${VDNAME[$i]}" mgmtdev vduse 2>&1|head -1
    sleep 3
  done
  # find each netdev and put it in its netns.  Auto-named eth*, one per vdpa
  # device.
  ETHS=""
  for n in $(ip -br link 2>/dev/null | awk '{print $1}'); do
    if [ -e /sys/class/net/$n/device/uevent ] && grep -qi vduse /sys/class/net/$n/device/uevent 2>/dev/null; then
      ETHS="$ETHS $n"
    fi
  done
  ETHS_ARR=($ETHS)
  for i in $(seq 0 $((NS-1))); do
    DEV=${ETHS_ARR[$i]:-}
    if [ -n "$DEV" ]; then
      sudo ip link set "$DEV" netns vdi$i 2>&1|head -1
      sudo ip netns exec vdi$i ip addr add 192.0.2.$((i+2))/24 dev "$DEV" 2>/dev/null
      sudo ip netns exec vdi$i ip link set "$DEV" up 2>&1|head -1
      VDEV[$i]="$DEV"
    fi
    echo "initiator $i netdev: [$DEV]"
  done
  sudo ip netns exec vdB ip link set r2dp-tap-inner up 2>/dev/null
  sudo ip netns exec vdB ip addr add $RESP_ADDR/24 dev r2dp-tap-inner 2>/dev/null
  echo "=== fwd ports ==="; grep -aE "dataplane ready|worker on lcore" $LOG | tail -8
}
# data-plane: install symmetric SAs per initiator + iperf3 from each
setup_sas() {
  for i in $(seq 0 $((NS-1))); do
    SPI_AB=$(printf "0xbeef%04x" $((i+1)))
    SPI_BA=$(printf "0xbeef%04x" $((i+1+1000)))
    SRC_I=$(printf "10.0.1.%d" $((i+1)))
    DEV=${VDEV[$i]:-}
    [ -z "$DEV" ] && continue
    sudo ip netns exec vdi$i ip addr add $SRC_I/32 dev lo 2>/dev/null
    sudo ip netns exec vdi$i ip addr add 10.0.2.0/24 dev "$DEV" 2>/dev/null
    sudo ip netns exec vdi$i ip xfrm state add src 192.0.2.$((i+2)) dst 192.0.2.1 proto esp spi $SPI_AB mode tunnel aead 'rfc4106(gcm(aes))' $HEXKEY 128 2>&1|head -1
    sudo ip netns exec vdi$i ip xfrm state add src 192.0.2.1 dst 192.0.2.$((i+2)) proto esp spi $SPI_BA mode tunnel aead 'rfc4106(gcm(aes))' $HEXKEY 128 2>&1|head -1
    sudo ip netns exec vdi$i ip xfrm policy add src $SRC_I/32 dst $RESP_ADDR/32 dir out tmpl src 192.0.2.$((i+2)) dst 192.0.2.1 proto esp mode tunnel 2>&1|head -1
    sudo ip netns exec vdi$i ip xfrm policy add src $RESP_ADDR/32 dst $SRC_I/32 dir in tmpl src 192.0.2.1 dst 192.0.2.$((i+2)) proto esp mode tunnel 2>&1|head -1
    sudo ip netns exec vdi$i ip route add $RESP_ADDR/32 dev "$DEV" 2>/dev/null
    INMAC=$(sudo ip netns exec vdB ip link show r2dp-tap-inner | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
    sudo ip netns exec vdi$i ip neigh replace 192.0.2.1 dev "$DEV" lladdr $INMAC 2>/dev/null
    sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock sa-add dir=in spi=$SPI_AB src=192.0.2.$((i+2)) dst=192.0.2.1 enc=aes-gcm-16 key=$KEY 2>&1|tail -1
    sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock sp-add dir=in action=protect src=$SRC_I/32 dst=$RESP_ADDR/32 tsrc=192.0.2.$((i+2)) tdst=192.0.2.1 2>&1|tail -1
    sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock sa-add dir=out spi=$SPI_BA src=192.0.2.1 dst=192.0.2.$((i+2)) enc=aes-gcm-16 key=$KEY 2>&1|tail -1
  done
  sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL /tmp/r2dp-dpdk.sock dump-sa 2>&1 | grep -c "SA spi" | xargs echo "fwd SAs:"
}
bench() {
  sudo ip netns exec vdB pkill -f "iperf3 -s" 2>/dev/null; sleep 1
  sudo ip netns exec vdB iperf3 -s -D -p 5201 --forceflush >/dev/null 2>&1
  sleep 2
  echo "=== ${NS}x parallel iperf3 UDP 2000M ==="
  PIDS=""
  for i in $(seq 0 $((NS-1))); do
    SRC_I=$(printf "10.0.1.%d" $((i+1)))
    sudo ip netns exec vdi$i timeout 20 iperf3 -B $SRC_I -c $RESP_ADDR -u -b 2000M -t 12 --forceflush > /home/yescorp/bench/results/vdm_nf$i.out 2>&1 &
    PIDS="$PIDS $!"
  done
  for p in $PIDS; do wait $p 2>/dev/null; done
  echo "=== per-stream ==="
  for i in $(seq 0 $((NS-1))); do
    echo "s$i: $(grep -A2 receiver /home/yescorp/bench/results/vdm_nf$i.out | grep -oE '[0-9.]+ (G|M)bits/sec|[0-9]+%\)' | tr '\n' ' ')"
  done
  echo "=== aggregate ==="
  grep -ohA2 "receiver" /home/yescorp/bench/results/vdm_nf*.out | grep -oE "[0-9.]+ (G|M)bits/sec" | awk '{gsub(/Mbits/,"");gsub(/Gbits/,"000");s+=$1}END{printf "aggregate receiver: %.3f Gbits/sec\n", s/1000000}'
  echo "=== forwarder ==="
  for i in $(seq 1 $NW); do
    grep -aE "worker on lcore $i" $LOG | tail -1
  done
  FP=$(pgrep -af "r2mc-fresh.*r2dp-fwd"|grep -v bash|awk '{print $1}'|head -1)
  sudo kill -USR1 $FP 2>/dev/null; sleep 1
  sudo grep -aE "stats rx=" $LOG | tail -1
}
case "${1:-}" in
  up) up; setup_sas; echo "== up done ==" ;;
  bench) bench ;;
  down) teardown; echo "== down done ==" ;;
  *) echo "usage: $0 {up|bench|down} NINIT=N NWORKERS=N" ;;
esac

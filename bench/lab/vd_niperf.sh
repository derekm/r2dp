#!/bin/bash
# TAP-FREE N-flow benchmark: N kernel-XFRM flows (distinct SPI + inner src)
# sharing the one VDUSE netdev eth0, N workers, distributor fans each SPI-flow
# to a separate worker -> saturates the box.  N parallel iperf3 streams.
set -u
LB=/home/yescorp/bench
MB=/home/yescorp/dpdk-mb-prefix
NFLOW="${NFLOW:-4}"
# derived inner srcs: 10.0.1.{1..N}; SPIs 0xbeef0000+i ; outer A=192.0.2.2 B=192.0.2.1
OUTER_A=192.0.2.2
OUTER_B=192.0.2.1
RESP_ADDR=10.0.2.1
HEXKEY=0x000102030405060708090a0b0c0d0e0f10111213
KEY=000102030405060708090a0b0c0d0e0f10111213

setup_flows() {
  # A: N out SAs + N in SAs (distinct SPI), plus per-flow inner src on lo
  for i in $(seq 1 $NFLOW); do
    SPI_AB=$(printf "0xbeef%04x" $i)      # A->B
    SPI_BA=$(printf "0xbeef%04x" $((i+1000)))  # B->A
    SRC_I=$(printf "10.0.1.%d" $i)
    # state (with distinct spi) — need distinct inner src too
    sudo ip netns exec nsA ip xfrm state add src $OUTER_A dst $OUTER_B proto esp spi $SPI_AB mode tunnel \
      aead 'rfc4106(gcm(aes))' $HEXKEY 128 2>&1|head -1
    sudo ip netns exec nsA ip xfrm state add src $OUTER_B dst $OUTER_A proto esp spi $SPI_BA mode tunnel \
      aead 'rfc4106(gcm(aes))' $HEXKEY 128 2>&1|head -1
    # per-flow selectors so iperf streams map to distinct SPIs
    sudo ip netns exec nsA ip xfrm policy add src $SRC_I/32 dst $RESP_ADDR/32 dir out tmpl src $OUTER_A dst $OUTER_B proto esp mode tunnel 2>&1|head -1
    sudo ip netns exec nsA ip xfrm policy add src $RESP_ADDR/32 dst $SRC_I/32 dir in tmpl src $OUTER_B dst $OUTER_A proto esp mode tunnel 2>&1|head -1
    # distinct inner source addr on lo
    sudo ip netns exec nsA ip addr add $SRC_I/32 dev lo 2>/dev/null
  done
  # forwarder: N inbound decrypt SAs (SPI distinct) + N outbound encrypt SAs
  CLT=/home/yescorp/r2mc-fresh/build-dpdk/tools/r2dpctl
  [ -x "$CLT" ] || CLT=$(find /home/yescorp/r2mc-fresh -name r2dpctl -type f|head -1)
  for i in $(seq 1 $NFLOW); do
    SPI_AB=$(printf "0xbeef%04x" $i)
    SPI_BA=$(printf "0xbeef%04x" $((i+1000)))
    SRC_I=$(printf "10.0.1.%d" $i)
    sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CLT /tmp/r2dp-dpdk.sock sa-add dir=in spi=$SPI_AB src=$OUTER_A dst=$OUTER_B enc=aes-gcm-16 key=$KEY 2>&1|tail -1
    sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CLT /tmp/r2dp-dpdk.sock sp-add dir=in action=protect src=$SRC_I/32 dst=$RESP_ADDR/32 tsrc=$OUTER_A tdst=$OUTER_B 2>&1|tail -1
    sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CLT /tmp/r2dp-dpdk.sock sa-add dir=out spi=$SPI_BA src=$OUTER_B dst=$OUTER_A enc=aes-gcm-16 key=$KEY 2>&1|tail -1
  done
  sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CLT /tmp/r2dp-dpdk.sock dump-sa 2>&1 | grep -c "SA spi" | xargs echo "fwd total SAs:"
}

bench() {
  sudo ip netns exec nsB pkill -f "iperf3 -s" 2>/dev/null; sleep 1
  sudo ip netns exec nsB iperf3 -s -D -p 5201 --forceflush >/dev/null 2>&1
  sleep 2
  echo "=== ${NFLOW}x parallel iperf3 UDP 2000M, 12s ==="
  PIDS=""
  for i in $(seq 1 $NFLOW); do
    SRC_I=$(printf "10.0.1.%d" $i)
    sudo ip netns exec nsA timeout 20 iperf3 -B $SRC_I -c $RESP_ADDR -u -b 2000M -t 12 --forceflush > /home/yescorp/bench/results/vdi_nf$i.out 2>&1 &
    PIDS="$PIDS $!"
  done
  for p in $PIDS; do wait $p 2>/dev/null; done
  echo "=== per-stream receiver lines ==="
  for i in $(seq 1 $NFLOW); do
    echo "stream $i: $(grep -A2 receiver /home/yescorp/bench/results/vdi_nf$i.out | grep -oE '[0-9.]+ (G|M)bits/sec|[0-9]+%\)' | tr '\n' ' ')"
  done
  echo "=== aggregate ==="
  grep -ohA2 "receiver" /home/yescorp/bench/results/vdi_nf*.out | grep -oE "[0-9.]+ (G|M)bits/sec" | awk '{gsub(/Mbits/,"");gsub(/Gbits/,"000");s+=$1}END{printf "aggregate receiver: %.3f Gbits/sec\n", s/1000000}'
  echo "=== forwarder ==="
  FP=$(pgrep -af "r2mc-fresh.*r2dp-fwd"|grep -v bash|awk '{print $1}'|head -1)
  sudo kill -USR1 $FP 2>/dev/null; sleep 1
  sudo grep -aE "stats rx=" /tmp/fwd_vdi.log | tail -1
}
case "${1:-}" in
  flows) setup_flows ;;
  bench) bench ;;
  *) echo "usage: $0 {flows|bench} NFLOW=N" ;;
esac

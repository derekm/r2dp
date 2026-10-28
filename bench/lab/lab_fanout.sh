#!/bin/bash
# A (fan-out) bring-up: forwarder with N per-worker inner tap vdevs, each
# wired to its own veth into B.  Decrypted inner from worker i lands on
# inner_tap_i -> veth_in_i -> B stack; B listens on all N.  Outer stays the
# shared r2dp-tap (distributor fans flows out to workers).
set -u
LB=/home/yescorp/bench
SRC=$LB/scripts
SESS="${R2DP_SESSION:-$LB/sessions/r2dpfan.sess}"
mkdir -p "$(dirname "$SESS")"; : > "$SESS"
N="${NINIT:-4}"
NW="${NWORKERS:-4}"
R2SRC=/home/yescorp/r2backend-fresh
FWD=/home/yescorp/r2mc-fresh/build-dpdk/fwd/r2dp-fwd
MB=/home/yescorp/dpdk-mb-prefix
FWDLD="LD_LIBRARY_PATH=$MB/lib64"
CFG=$LB/configs
CB=$CFG/racoonBmulti.conf
L2="LD_LIBRARY_PATH=${R2SRC}/lib/.libs:/home/yescorp/r2dp-prefix/lib64"
X=/home/yescorp/xfrm-prefix
# build the --vdev list: outer tap0 (r2dp-tap) + shared inner tap1
# (r2dp-tap-inner) + N fan-out inner taps (r2dp-inner<i>)
VDEVS="--vdev=crypto_aesni_mb0 --vdev=net_tap0,iface=r2dp-tap --vdev=net_tap1,iface=r2dp-tap-inner"
for i in $(seq 0 $((N-1))); do VDEVS="$VDEVS --vdev=net_tap$((i+2)),iface=r2dp-inner$i"; done

$SRC/bench_teardown3.sh "$SESS" >/dev/null 2>&1 || true
for i in $(seq 0 $((N-1))); do sudo ip netns del nsI$i 2>/dev/null; done
sudo ip netns del nsB 2>/dev/null
sudo ip link del br0 2>/dev/null
sudo rm -rf $LB/resume-B; mkdir -p $LB/resume-B; chmod 777 $LB/resume-B

sudo ip netns add nsB
sudo ip netns exec nsB ip link set lo up
sudo ip netns exec nsB ip link add br0 type bridge
sudo ip netns exec nsB ip link set br0 up
# total lcores: outer+headroom = NW workers + 1 distributor + shared inner poll
# (-l 0-... need NW+2 minimum for 4 workers + dist)
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env $FWDLD bash -c "$FWD -n $NW -v -s /tmp/r2dp-dpdk.sock --no-pci -l 0-$((NW+3)) $VDEVS > /tmp/fwd_fan.log 2>&1"
sleep 8
sudo ip netns exec nsB ip link set r2dp-tap master br0 2>/dev/null
sudo ip netns exec nsB ip link set r2dp-tap up 2>/dev/null
sudo ip netns exec nsB ip link set r2dp-tap-inner up 2>/dev/null
sudo ip netns exec nsB ip link set r2dp-tap-inner promisc on 2>/dev/null
sudo ip netns exec nsB ip addr add 10.77.0.1/32 dev r2dp-tap-inner 2>/dev/null
sudo ip netns exec nsB ip addr add 192.0.2.1/24 dev r2dp-tap-inner 2>/dev/null
sudo ip netns exec nsB ip route add 10.77.0.0/24 dev r2dp-tap-inner 2>/dev/null
sudo ip netns exec nsB sysctl -w net.ipv4.conf.all.accept_local=1 >/dev/null 2>&1
# B responder daemons
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env R2DP_ROLE=spmd R2DP_SOCK=/tmp/r2dp-dpdk.sock $L2 $R2SRC/spmd/.libs/spmd -F -f $CB
sleep 4
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env R2DP_ROLE=iked R2DP_SOCK=/tmp/r2dp-dpdk.sock $L2 RACOON2_RESUME_DIR=$LB/resume-B RACOON2_ADMIN_SOCK=/tmp/iked.sock-B $R2SRC/iked/.libs/iked -F -f $CB -d -l /tmp/ikedB.log
echo "B launched"; sleep 10
# fan-out inner taps: each worker's tap goes to its own veth into B stack
INMAC="$(sudo ip netns exec nsB ip link show r2dp-tap-inner | grep -oE '[0-9a-f]{2}(:[0-9a-f]{2}){5}' | head -1)"
# we use ONLY the fan-out taps for data; give B an IP + route on each fan veth
for i in $(seq 0 $((N-1))); do
  sudo ip link add vfi${i}a type veth peer name vfi${i}b
  sudo ip link set vfi${i}b netns nsB
  sudo ip netns exec nsB ip link set vfi${i}b up
  sudo ip link set vfi${i}a netns nsB
  sudo ip netns exec nsB ip link set vfi${i}a up
  # connect: fan tap (r2dp-inner<i>) <-> vfi-b (B stack) via a pair.  net_tap
  # creates iface r2dp-inner<i> IN the forwarder's netns (nsB).  So bridge
  # r2dp-inner<i> and vfi-b in br0, or set addresses.
  sudo ip netns exec nsB ip link set vfi${i}b master br0 2>/dev/null
  sudo ip netns exec nsB ip link set r2dp-inner$i master br0 2>/dev/null
  sudo ip netns exec nsB ip link set r2dp-inner$i up 2>/dev/null
  sudo ip netns exec nsB ip link set r2dp-inner$i promisc on 2>/dev/null
done
# B stack on the SHARED inner tap carries IKE/control; fan-out taps carry data
# -> pin B's data IP on r2dp-tap-inner (192.0.2.1) already done.  Fan veths get
# an alias so B sees worker traffic on any of them.
for i in $(seq 0 $((N-1))); do
  sudo ip netns exec nsB ip addr add 192.0.2.$((10+i))/32 dev vfi${i}b 2>/dev/null
  sudo ip netns exec nsB ip link set vfi${i}b promisc on 2>/dev/null
done

# N initiators (kernel XFRM -> forwarder), same as lab_up
for i in $(seq 0 $((N-1))); do
  outer="10.77.0.$((2+i))"; inner="192.0.2.$((2+i))"
  sudo ip netns add nsI$i
  sudo ip link add vi${i}a type veth peer name vi${i}b
  sudo ip link set vi${i}a netns nsI$i
  sudo ip link set vi${i}b netns nsB
  sudo ip netns exec nsB ip link set vi${i}b master br0
  sudo ip netns exec nsB ip link set vi${i}b up
  sudo ip netns exec nsI$i ip link set lo up
  sudo ip netns exec nsI$i ip link set vi${i}a up
  sudo ip netns exec nsI$i ip addr add $outer/24 dev vi${i}a
  sudo ip netns exec nsI$i ip link add dummyI$i type dummy 2>/dev/null
  sudo ip netns exec nsI$i ip link set dummyI$i up
  sudo ip netns exec nsI$i ip addr add $inner/32 dev dummyI$i 2>/dev/null
  sudo ip netns exec nsI$i ip route add 192.0.2.0/24 dev dummyI$i 2>/dev/null
  sudo ip netns exec nsI$i ip neigh replace 10.77.0.1 lladdr $INMAC dev vi${i}a 2>/dev/null
  $SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsI$i env LD_LIBRARY_PATH=$X/lib $X/sbin/spmd -F -f $CFG/racoonA${i}.conf
done
sleep 4
for i in $(seq 0 $((N-1))); do
  $SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsI$i env LD_LIBRARY_PATH=$X/lib RACOON2_RESUME_DIR=$LB/resume-A RACOON2_ADMIN_SOCK=/tmp/ikedA.sock-${i} $X/sbin/iked -F -f $CFG/racoonA${i}.conf -d -I 10.77.0.1 -S sel_out -l /tmp/ikedA${i}.log
done
echo "initiators launched (workers=$NW, fan taps=$N)"; sleep 30
echo "=== workers + fan ports ==="
grep -aE "worker on lcore|DPDK dataplane ready" /tmp/fwd_fan.log 2>/dev/null | tail -8
echo "=== pings ==="
ok=0; for i in $(seq 0 $((N-1))); do sudo ip netns exec nsI$i ping -c2 -W1 192.0.2.1 >/dev/null 2>&1 && ok=$((ok+1)); done; echo "$ok/$N"
echo "session: $(cat $SESS | tr '\n' ' ')"

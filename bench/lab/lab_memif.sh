#!/bin/bash
# Memif inner-leg bring-up: forwarder decrypted-inner TX goes over memif
# (zero-copy, no kernel tap) to testpmd (B-side client) instead of net_tap.
# Outer stays net_tap0 (IKE/ESP).  Measures forwarder ESP rate with NO inner
# tap crossing.
set -u
LB=/home/yescorp/bench
SRC=$LB/scripts
SESS="${R2DP_SESSION:-$LB/sessions/r2dpmemif.sess}"
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
MEMIF=/tmp/memif/r2dp.sock
sudo mkdir -p /tmp/memif; sudo chmod 777 /tmp/memif; sudo rm -f $MEMIF

$SRC/bench_teardown3.sh "$SESS" >/dev/null 2>&1 || true
for i in $(seq 0 $((N-1))); do sudo ip netns del nsI$i 2>/dev/null; done
sudo ip netns del nsB 2>/dev/null
sudo ip netns del nsT 2>/dev/null
sudo ip link del br0 2>/dev/null
sudo rm -rf $LB/resume-B; mkdir -p $LB/resume-B; chmod 777 $LB/resume-B
sudo rm -rf /var/run/dpdk/rte

sudo ip netns add nsB
sudo ip netns exec nsB ip link set lo up
sudo ip netns exec nsB ip link add br0 type bridge
sudo ip netns exec nsB ip link set br0 up
# forwarder: outer tap (IKE/ESP) + INNER MEMIF server
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env $FWDLD bash -c "$FWD -n $NW -v -s /tmp/r2dp-dpdk.sock --no-pci -l 0-$((NW+2)) --vdev=crypto_aesni_mb0 --vdev=net_tap0,iface=r2dp-tap --vdev=net_memif,role=server,socket=$MEMIF,id=0 > /tmp/fwd_memif.log 2>&1"
sleep 8
sudo ip netns exec nsB ip link set r2dp-tap master br0 2>/dev/null
sudo ip netns exec nsB ip link set r2dp-tap up 2>/dev/null
sudo ip netns exec nsB ip addr add 10.77.0.1/32 dev r2dp-tap 2>/dev/null
sudo ip netns exec nsB ip addr add 192.0.2.1/24 dev r2dp-tap 2>/dev/null
# B responder daemons (control plane only; data goes memif->testpmd)
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env R2DP_ROLE=spmd R2DP_SOCK=/tmp/r2dp-dpdk.sock $L2 $R2SRC/spmd/.libs/spmd -F -f $CB
sleep 4
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env R2DP_ROLE=iked R2DP_SOCK=/tmp/r2dp-dpdk.sock $L2 RACOON2_RESUME_DIR=$LB/resume-B RACOON2_ADMIN_SOCK=/tmp/iked.sock-B $R2SRC/iked/.libs/iked -F -f $CB -d -l /tmp/ikedB.log
echo "B launched"; sleep 10
# testpmd memif client draining inner (B-side endpoint)
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsT env $FWDLD RTE_DRIVER_DIR=$MB/lib64/dpdk/pmds-26.0 bash -c "ip netns exec nsB true" >/dev/null 2>&1
sudo ip netns del nsT 2>/dev/null
# run testpmd IN nsB (same memif socket / hugepages)
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env $FWDLD RTE_DRIVER_DIR=$MB/lib64/dpdk/pmds-26.0 $MB/bin/dpdk-testpmd -l 8-11 --no-pci --file-prefix=tpm --vdev=net_memif,role=client,socket=$MEMIF,id=0 -- -i --rxd=512 --txd=512 --mbuf-size=2048 > /tmp/tpmemif.log 2>&1
echo "testpmd launched (memif client)"
# initiators
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
  INMAC=$(sudo ip netns exec nsB ip link show r2dp-tap | grep -oE '[0-9a-f]{2}(:[0-9a-f]{2}){5}' | head -1)
  sudo ip netns exec nsI$i ip neigh replace 10.77.0.1 lladdr $INMAC dev vi${i}a 2>/dev/null
  $SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsI$i env LD_LIBRARY_PATH=$X/lib $X/sbin/spmd -F -f $CFG/racoonA${i}.conf
done
sleep 4
for i in $(seq 0 $((N-1))); do
  $SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsI$i env LD_LIBRARY_PATH=$X/lib RACOON2_RESUME_DIR=$LB/resume-A RACOON2_ADMIN_SOCK=/tmp/ikedA.sock-${i} $X/sbin/iked -F -f $CFG/racoonA${i}.conf -d -I 10.77.0.1 -S sel_out -l /tmp/ikedA${i}.log
done
echo "initiators launched"; sleep 30
echo "=== fwd: which ports ==="
grep -aE "worker on lcore|DPDK dataplane ready|inner=" /tmp/fwd_memif.log 2>/dev/null | tail -6
echo "=== testpmd memif link ==="
grep -aE "link|state|num|queue" /tmp/tpmemif.log 2>/dev/null | tail -5
echo "=== pings ==="
ok=0; for i in $(seq 0 $((N-1))); do sudo ip netns exec nsI$i ping -c2 -W1 192.0.2.1 >/dev/null 2>&1 && ok=$((ok+1)); done; echo "$ok/$N"
echo "session: $(cat $SESS | tr '\n' ' ')"

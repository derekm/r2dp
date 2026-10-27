#!/bin/bash
# Data-driven N-initiator lab bring-up on .179.  Reads lab.manifest (emitted
# by gen_lab_conf.py) and drives everything from it -- no hardcoded initiator
# names or addresses.  N flows -> N outer src IPs -> spread across net_tap
# queues -> N forwarder workers.
set -u
LB="${LB:-/home/yescorp/bench}"
SRC="$LB/scripts"
CFG="${CFG:-$LB/configs}"
MANIFEST="$CFG/lab.manifest"
[ -f "$MANIFEST" ] || { echo "no manifest; run gen_lab_conf.py first"; exit 2; }
. "$MANIFEST"   # NINIT, OUTER_BASE, INNER_BASE, RESP_OUTER, RESP_INNER, CFG, PSK, I0..I{n-1}

SESS="${R2DP_SESSION:-$LB/sessions/r2dpmulti.sess}"
mkdir -p "$(dirname "$SESS")"; : > "$SESS"
R2SRC=/home/yescorp/r2backend-fresh
FWD=/home/yescorp/r2mc-fresh/build-dpdk/fwd/r2dp-fwd
MB=/home/yescorp/dpdk-mb-prefix
FWDLD="LD_LIBRARY_PATH=$MB/lib64"
CB=$CFG/racoonBmulti.conf
L2="LD_LIBRARY_PATH=${R2SRC}/lib/.libs:/home/yescorp/r2dp-prefix/lib64"
X=/home/yescorp/xfrm-prefix
NW="${NWORKERS:-$NINIT}"

# gather initiator fields from the manifest into index arrays
IDX=(); NS=(); OUT=(); INN=(); DUM=(); SPMS=(); IKS=(); IKLOG=(); LID=()
for i in $(seq 0 $((NINIT-1))); do
  eval "row=\$I$i"
  IFS=: read -r idx ns ouc inc dum spms iks iklog lid <<< "$row"
  IDX+=($idx); NS+=($ns); OUT+=($ouc); INN+=($inc); DUM+=($dum); SPMS+=($spms); IKS+=($iks); IKLOG+=($iklog); LID+=($lid)
done

$SRC/bench_teardown3.sh "$SESS" >/dev/null 2>&1 || true
for ns in "${NS[@]}"; do sudo ip netns del "$ns" 2>/dev/null; done
sudo ip netns del nsB 2>/dev/null
sudo ip link del br0 2>/dev/null
sudo rm -rf $LB/resume-B; mkdir -p $LB/resume-B; chmod 777 $LB/resume-B

# ---- responder nsB: forwarder + r2dp iked ----
sudo ip netns add nsB
sudo ip netns exec nsB ip link set lo up
sudo ip netns exec nsB ip link add br0 type bridge
sudo ip netns exec nsB ip link set br0 up
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env $FWDLD bash -c "$FWD -n $NW -v -s /tmp/r2dp-dpdk.sock --no-pci -l 0-$((NW)) --vdev=crypto_aesni_mb0 --vdev=net_tap0,iface=r2dp-tap --vdev=net_tap1,iface=r2dp-tap-inner > /tmp/fwd_i.log 2>&1"
sleep 8
sudo ip netns exec nsB ip link set r2dp-tap master br0 2>/dev/null
sudo ip netns exec nsB ip link set r2dp-tap up 2>/dev/null
sudo ip netns exec nsB ip link set r2dp-tap-inner up 2>/dev/null
sudo ip netns exec nsB ip link set r2dp-tap-inner promisc on 2>/dev/null
sudo ip netns exec nsB ip addr add "$RESP_OUTER/32" dev r2dp-tap-inner 2>/dev/null
sudo ip netns exec nsB ip addr add "$RESP_INNER/24" dev r2dp-tap-inner 2>/dev/null
sudo ip netns exec nsB ip route add "${RESP_INNER%.*}.0/24" dev r2dp-tap-inner 2>/dev/null
sudo ip netns exec nsB ip route add "${RESP_OUTER%.*}.0/24" dev r2dp-tap-inner 2>/dev/null
sudo ip netns exec nsB sysctl -w net.ipv4.conf.all.accept_local=1 >/dev/null 2>&1
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env R2DP_ROLE=spmd R2DP_SOCK=/tmp/r2dp-dpdk.sock $L2 $R2SRC/spmd/.libs/spmd -F -f $CB
sleep 4
$SRC/bench_spawn3.sh "$SESS" sudo ip netns exec nsB env R2DP_ROLE=iked R2DP_SOCK=/tmp/r2dp-dpdk.sock $L2 RACOON2_RESUME_DIR=$LB/resume-B RACOON2_ADMIN_SOCK=/tmp/iked.sock-B $R2SRC/iked/.libs/iked -F -f $CB -d -l /tmp/ikedB.log
echo "B launched"; sleep 10
INMAC=$(sudo ip netns exec nsB ip link show r2dp-tap-inner | grep -oE '[0-9a-f]{2}(:[0-9a-f]{2}){5}' | head -1)

# ---- N initiators, each own veth into br0 ----
for k in "${!NS[@]}"; do
  ns=${NS[$k]}; ouc=${OUT[$k]}; inc=${INN[$k]}; dum=${DUM[$k]}
  sudo ip netns add "$ns"
  sudo ip link add "vi${k}a" type veth peer name "vi${k}b"
  sudo ip link set "vi${k}a" netns "$ns"
  sudo ip link set "vi${k}b" netns nsB
  sudo ip netns exec nsB ip link set "vi${k}b" master br0
  sudo ip netns exec nsB ip link set "vi${k}b" up
  sudo ip netns exec "$ns" ip link set lo up
  sudo ip netns exec "$ns" ip link set "vi${k}a" up
  sudo ip netns exec "$ns" ip addr add "$ouc/24" dev "vi${k}a"
  sudo ip netns exec "$ns" ip link add "$dum" type dummy 2>/dev/null
  sudo ip netns exec "$ns" ip link set "$dum" up
  sudo ip netns exec "$ns" ip addr add "$inc/32" dev "$dum" 2>/dev/null
  sudo ip netns exec "$ns" ip route add "${RESP_INNER%.*}.0/24" dev "$dum" 2>/dev/null
  sudo ip netns exec "$ns" ip neigh replace "$RESP_OUTER" lladdr $INMAC dev "vi${k}a" 2>/dev/null
  $SRC/bench_spawn3.sh "$SESS" sudo ip netns exec "$ns" env LD_LIBRARY_PATH=$X/lib $X/sbin/spmd -F -f $CFG/racoonA${k}.conf
done
sleep 4
for k in "${!NS[@]}"; do
  $SRC/bench_spawn3.sh "$SESS" sudo ip netns exec "${NS[$k]}" env LD_LIBRARY_PATH=$X/lib RACOON2_RESUME_DIR=$LB/resume-A RACOON2_ADMIN_SOCK=${IKS[$k]} $X/sbin/iked -F -f $CFG/racoonA${k}.conf -d -I "$RESP_OUTER" -S sel_out -l ${IKLOG[$k]}
done
echo "$NINIT initiators launched (workers=$NW)"; sleep 30

echo "=== control plane ==="
sudo grep -ac "SA_ADD" /tmp/fwd_i.log 2>/dev/null
ok=0
for k in "${!NS[@]}"; do
  sudo ip netns exec "${NS[$k]}" ping -c2 -W1 "$RESP_INNER" >/dev/null 2>&1 && ok=$((ok+1))
done
echo "initiators pinging: $ok/$NINIT"
echo "session: $(cat $SESS | tr '\n' ' ')"

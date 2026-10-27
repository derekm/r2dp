#!/bin/bash
# Data-driven teardown for the N-initiator lab.
set -u
LB="${LB:-/home/yescorp/bench}"
CFG="${CFG:-$LB/configs}"
SRC="$LB/scripts"
SESS="${R2DP_SESSION:-$LB/sessions/r2dpmulti.sess}"
# teardown only recorded PGIDs; never names/paths (prod /usr/local/racoon2 safety)
$SRC/bench_teardown3.sh "$SESS"
# remove initiator netns + veths (manifest-driven, no hardcoded names)
if [ -f "$CFG/lab.manifest" ]; then
  . "$CFG/lab.manifest"
  for i in $(seq 0 $((NINIT-1))); do
    eval "row=\$I$i"; IFS=: read -r idx ns _ _ _ _ _ _ _ <<< "$row"
    sudo ip netns del "$ns" 2>/dev/null
    sudo ip link del "vi${i}b" 2>/dev/null
  done
fi
sudo ip netns del nsB 2>/dev/null
sudo ip link del br0 2>/dev/null
sudo rm -rf /var/run/dpdk/rte
echo "lab torn down"

#!/bin/bash
# p4_mc_bench.sh -- P4 multicore (slices R2DP_P4_WORKERS=N) tap-free sweep.
# Spawns N independent pipeline replicas; each bench worker self-injects and
# reports its own slice throughput.  Aggregate Mpps = sum over slices.
#   p4_mc_bench.sh HOST BINDIR SPEC SCRATCH SOCK PMD SIZE [WORKERS...]
set -u
H="${1:?host}"; B="${2:?bindir}"; SPEC="${3:?spec}"
SCRATCH="${4:?scratch}"; SOCK="${5:?sock}"; PMD="${6:?pmd}"; SIZE="${7:?size}"
shift 7
WORKERS="${@:-1 2 4}"
KEY=00112233445566778899aabbccddeeff00112233
run() { ssh -o ConnectTimeout=30 "$H" "$@"; }
run "mkdir -p $SCRATCH"
for W in $WORKERS; do
  LOG=/tmp/p4mc_${PMD}_${SIZE}_w${W}.log
  run "sudo -n pgrep -x r2dp-fwd | xargs -r sudo -n kill -9 2>/dev/null; \
       sudo -n rm -f $SOCK; sudo -n rm -rf /run/user/0/dpdk/r2q; sleep 1; \
       cd $B; : > $LOG; \
       sudo -n env R2DP_P4_BENCH=1 R2DP_P4_BENCH_SIZE=$SIZE \
         R2DP_P4_WORKERS=$W R2DP_P4_SPEC=$SPEC R2DP_P4_SCRATCH=$SCRATCH \
         R2DP_SWX_SRC=/home/yescorp/dpdk-src \
         nohup ./fwd/r2dp-fwd --dp p4 -s $SOCK \
         --vdev=net_tap0,iface=r2po --vdev=net_tap1,iface=r2pi \
         --vdev=crypto_${PMD}0 --no-huge --no-pci -m 1024 --file-prefix r2q \
         > $LOG 2>&1 & \
       sleep 8; \
       cd $B; \
       sudo -n env R2DP_SOCK=$SOCK ./r2dpctl $SOCK sa-add dir=out spi=0x2001 \
         src=192.0.2.1 dst=203.0.113.1 enc=aes-gcm-16 key=$KEY >/dev/null 2>&1; \
       sudo -n env R2DP_SOCK=$SOCK ./r2dpctl $SOCK sp-add dir=out action=protect \
         src=10.0.0.1/32 dst=10.0.0.2/32 proto=udp tsrc=192.0.2.1 tdst=203.0.113.1; \
       sleep 25; \
       sudo -n pkill -9 -x r2dp-fwd 2>/dev/null; sleep 1"
  echo "--- $PMD size=$SIZE workers=$W ---"
  run "grep -E 'slices=|bench\\[|bench: best|no bound|dataplane' $LOG | tail -20"
done

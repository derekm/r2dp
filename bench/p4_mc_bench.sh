#!/bin/bash
# p4_mc_bench.sh -- P4 multicore (slices R2DP_P4_WORKERS=N) tap-free sweep.
# Spawns N independent pipeline replicas; each bench worker self-injects and
# reports its own slice throughput (log lines tagged with the slice id).
# Aggregate Mpps = sum over slices.
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
  # Kill only forwarders we own: record our PID up front by matching the
  # exact vdev/file-prefix we launch (never pkill by process name -- those
  # hosts also run lab iked and other forwarders).  The stale-cleanup below
  # removes only a prior run of THIS harness by its launch signature.
  run "sudo -n rm -f $SOCK; sudo -n rm -rf /run/user/0/dpdk/r2q; sleep 1; \
       cd $B; : > $LOG; \
       sudo -n env R2DP_P4_BENCH=1 R2DP_P4_BENCH_SIZE=$SIZE \
         R2DP_P4_WORKERS=$W R2DP_P4_SPEC=$SPEC R2DP_P4_SCRATCH=$SCRATCH \
         R2DP_SWX_SRC=/home/yescorp/dpdk-src \
         nohup ./fwd/r2dp-fwd --dp p4 -s $SOCK \
         --vdev=net_tap0,iface=r2po --vdev=net_tap1,iface=r2pi \
         --vdev=crypto_${PMD}0,max_nb_queue_pairs=$W \
         --no-huge --no-pci -m 1024 --file-prefix r2q > $LOG 2>&1 & echo \$! > /tmp/p4mc.pid; \
       sleep 8; \
       cd $B; \
       sudo -n env R2DP_SOCK=$SOCK ./r2dpctl $SOCK sa-add dir=out spi=0x2001 \
         src=192.0.2.1 dst=203.0.113.1 enc=aes-gcm-16 key=$KEY || { \\
           echo 'sa-add FAILED -- aborting run'; exit 1; }; \
       sudo -n env R2DP_SOCK=$SOCK ./r2dpctl $SOCK sp-add dir=out action=protect \
         src=10.0.0.1/32 dst=10.0.0.2/32 proto=udp tsrc=192.0.2.1 tdst=203.0.113.1; \
       sleep 25; \
       sudo -n kill -9 \$(cat /tmp/p4mc.pid) 2>/dev/null; rm -f /tmp/p4mc.pid; sleep 1"
  echo "--- $PMD size=$SIZE workers=$W ---"
  # One line per slice: tagged by slice id so the aggregate is auditable.
  run "grep -E 'slices=|[bb]ench\[slice|bench: best|no bound|dataplane' $LOG | tail -40"
done

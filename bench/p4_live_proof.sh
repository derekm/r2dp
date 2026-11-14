#!/bin/bash
# Live-path proof for the P4 multicore steering (single RX+TX io_worker) on
# .165: launch r2dp-fwd --dp p4 live (NO bench) with R2DP_P4_WORKERS=N, install
# an outbound SA + /32,/32 udp PROTECT, inject clear IPv4/UDP on the inner tap,
# and confirm the dataplane counters MOVE -> the io_worker steered each frame to
# a slice and the per-slice worker pipeline+extern forwarded + TX'd it.
# With SPDEL=1: delete the OUT PROTECT and re-inject to show the post-delete
# frames are now DISCARDED (ob_miss / a7) rather than forwarded as ESP.
#
# This bootstrap itself is SCP'd to the box and run there, so the kill/cleanup
# patterns do NOT appear in the local harness argv (kill hygiene: never kill by
# a name/pattern that matches this script).  The forwarder PID is captured with
# a socket-keyed `pgrep` (never sudo's $!); the recorded PID is killed with
# `sudo` (a root forwarder is not reaped by an unprivileged SIGKILL).  Any
# remote step that fails aborts the run -- the ssh exit status is checked.
#
#   p4_live_proof.sh [workers] [frames] [spdel]
set -u
W="${1:-2}"; FRAMES="${2:-80000}"; SPDEL="${3:-0}"
H=yescorp@192.168.0.165
B=/home/yescorp/r2dp-p4
KEY=00112233445566778899aabbccddeeff00112233
run() { ssh -o ConnectTimeout=25 "$H" "$@"; }

cat > /tmp/p4_live_probe.sh <<EOF
#!/bin/bash
set -euo pipefail
B=/home/yescorp/r2dp-p4; W="$W"; KEY="$KEY"; FRAMES="$FRAMES"; SPDEL="$SPDEL"
CLEAN() {
    [ -f /tmp/lp.pid ] && sudo -n kill -9 \$(cat /tmp/lp.pid) 2>/dev/null || true
    sudo -n rm -f /tmp/lp.pid /tmp/lp.sock 2>/dev/null || true
}
trap CLEAN EXIT
[ -f /tmp/lp.pid ] && sudo -n kill -9 \$(cat /tmp/lp.pid) 2>/dev/null || true
sudo -n rm -f /tmp/lp.pid /tmp/lp.sock 2>/dev/null || true
sudo -n rm -f /tmp/lp.sock
sudo -n rm -rf /run/user/0/dpdk/r2q
sudo -n ip link del r2po 2>/dev/null || true; sudo -n ip link del r2pi 2>/dev/null || true
sleep 1
cd $B
setsid nohup sudo -n env R2DP_P4_WORKERS=\$W R2DP_P4_SPEC=$B/p4/r2dp.out \
  R2DP_P4_SCRATCH=$B/scratch R2DP_SWX_SRC=/home/yescorp/dpdk-src \
  ./build/fwd/r2dp-fwd --dp p4 -s /tmp/lp.sock \
  --vdev=net_tap0,iface=r2po --vdev=net_tap1,iface=r2pi \
  --vdev=crypto_openssl0,max_nb_queue_pairs=\$W --no-huge --no-pci -m 1024 \
  --file-prefix r2q > /tmp/livep.log 2>&1 < /dev/null &
sleep 9
FP=\$(sudo -n pgrep -f "r2dp-fwd --dp p4 -s /tmp/lp.sock" | head -1)
[ -n "\$FP" ] || { echo "FAIL: forwarder did not start"; exit 1; }
echo \$FP > /tmp/lp.pid
echo "fwd pid=\$FP"
grep -E 'slices|distributor|ready|I/O:.*outer' /tmp/livep.log | head -6
cd $B/build
sudo -n env R2DP_SOCK=/tmp/lp.sock ./r2dpctl /tmp/lp.sock sa-add dir=out spi=0x2001 \
  src=192.0.2.1 dst=203.0.113.1 enc=aes-gcm-16 key=\$KEY \
  || { echo "FAIL: sa-add rejected/control socket down"; exit 1; }
sudo -n env R2DP_SOCK=/tmp/lp.sock ./r2dpctl /tmp/lp.sock sp-add dir=out action=protect \
  src=10.0.0.1/32 dst=10.0.0.2/32 proto=udp tsrc=192.0.2.1 tdst=203.0.113.1 \
  || { echo "FAIL: sp-add rejected"; exit 1; }
sleep 2
echo "forwarder up, SA+SP installed"
grep -E 'BIND installed' /tmp/livep.log | head -4

cat > /tmp/liveinj.py <<PY
import socket, struct, time, sys
i=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); i.bind(("r2pi",0))
ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+8,0,0,64,17,0,socket.inet_aton("10.0.0.1"),socket.inet_aton("10.0.0.2"))
ud=struct.pack("!HHHH",1024,9,8,0)
f=bytes.fromhex("0200010203040200000000010800")+ip+ud+bytes(16)
for _ in range(int(sys.argv[1])): i.send(f)
time.sleep(2.0)
print("injected", sys.argv[1])
PY
sudo -n python3 /tmp/liveinj.py \$FRAMES
sleep 1
echo "=== after inject: in_rx / out0 ESP / a6 PROTECT ==="
grep -E 'pkt:.*a[567]' /tmp/livep.log | tail -4
echo "=== crypto enq/deq ==="
grep 'crypto:' /tmp/livep.log | tail -2

if [ "\$SPDEL" = "1" ]; then
    echo "=== sp-del + re-inject (delete proof) ==="
    sudo -n env R2DP_SOCK=/tmp/lp.sock ./r2dpctl /tmp/lp.sock sp-del dir=out \
      src=10.0.0.1/32 dst=10.0.0.2/32 proto=udp \
      || { echo "FAIL: sp-del rejected"; exit 1; }
    sleep 1
    sudo -n python3 /tmp/liveinj.py \$FRAMES
    sleep 1
    echo "=== after sp-del: policy DISCARDed (ob_miss / a7) ==="
    grep -E 'pkt:.*a[567]|sp_del|DEL' /tmp/livep.log | tail -4
fi
EOF
scp -q /tmp/p4_live_probe.sh "$H":/home/yescorp/r2dp-p4/live_probe.sh
run "bash $B/live_probe.sh 2>&1" || { echo "FAIL: remote proof returned nonzero"; exit 1; }
echo "done (remote proof rc=0)"

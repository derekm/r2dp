#!/bin/bash
# Live-path proof for the P4 multicore steering (single RX+TX io_worker) on
# .165: launch r2dp-fwd --dp p4 live (NO bench) with R2DP_P4_WORKERS=N, install
# an outbound SA + /32,/32 udp PROTECT, inject clear IPv4/UDP on the inner tap,
# and confirm the dataplane counters MOVE -> the io_worker steered each frame to
# a slice and the per-slice worker pipeline+extern forwarded + TX'd it.
#
# This bootstrap itself is SCP'd to the box and run there, so the kill/cleanup
# patterns do NOT appear in the local harness argv (kill hygiene: never kill by
# a name/pattern that matches this script).  Forwarder is launched with setsid
# so its PID file names the real process, not sudo's.
#
#   p4_live_proof.sh [workers] [frames]
set -u
W="${1:-2}"; FRAMES="${2:-80000}"
H=yescorp@192.168.0.165
B=/home/yescorp/r2dp-p4
KEY=00112233445566778899aabbccddeeff00112233
run() { ssh -o ConnectTimeout=25 "$H" "$@"; }

# write + run the remote launcher/probe all in one go
cat > /tmp/p4_live_probe.sh <<EOF
#!/bin/bash
set -u
B=/home/yescorp/r2dp-p4; W="$W"; KEY="$KEY"; FRAMES="$FRAMES"
# kill a PRIOR probe's forwarder only, by its recorded PID (never a name pattern)
[ -f /tmp/lp.pid ] && kill -9 \$(cat /tmp/lp.pid) 2>/dev/null
rm -f /tmp/lp.pid
sudo -n rm -f /tmp/lp.sock
sudo -n rm -rf /run/user/0/dpdk/r2q
sudo -n ip link del r2po 2>/dev/null; sudo -n ip link del r2pi 2>/dev/null
sleep 1
cd $B
setsid nohup sudo -n env R2DP_P4_WORKERS=\$W R2DP_P4_SPEC=$B/p4/r2dp.out \
  R2DP_P4_SCRATCH=$B/scratch R2DP_SWX_SRC=/home/yescorp/dpdk-src \
  ./build/fwd/r2dp-fwd --dp p4 -s /tmp/lp.sock \
  --vdev=net_tap0,iface=r2po --vdev=net_tap1,iface=r2pi \
  --vdev=crypto_openssl0,max_nb_queue_pairs=\$W --no-huge --no-pci -m 1024 \
  --file-prefix r2q > /tmp/livep.log 2>&1 < /dev/null &
echo \$! > /tmp/lp.pid
sleep 9
cd $B/build
sudo -n env R2DP_SOCK=/tmp/lp.sock ./r2dpctl /tmp/lp.sock sa-add dir=out spi=0x2001 \
  src=192.0.2.1 dst=203.0.113.1 enc=aes-gcm-16 key=\$KEY \
  || { echo "FAIL: sa-add rejected/control socket down"; exit 1; }
sudo -n env R2DP_SOCK=/tmp/lp.sock ./r2dpctl /tmp/lp.sock sp-add dir=out action=protect \
  src=10.0.0.1/32 dst=10.0.0.2/32 proto=udp tsrc=192.0.2.1 tdst=203.0.113.1 \
  || { echo "FAIL: sp-add rejected"; exit 1; }
sleep 2
echo "forwarder up, SA+SP installed"
grep -E 'slices|distributor|ready|I/O:.*outer|BIND installed' /tmp/livep.log | head -12

# inject FRAMES clear IPv4/UDP on the inner tap -> PROTECT -> ESP on outer (out0)
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
cd $B && sudo -n python3 liveinj.py \$FRAMES 2>&1
sleep 1
echo "=== dataplane counters (in_rx / out0 ESP) ==="
grep -E 'pkt:.*a[567]' /tmp/livep.log | tail -4
echo "=== crypto enq/deq ==="
grep 'crypto:' /tmp/livep.log | tail -2
EOF
scp -q /tmp/p4_live_probe.sh "$H":/home/yescorp/r2dp-p4/live_probe.sh
run "bash $B/live_probe.sh 2>&1"

echo "done"

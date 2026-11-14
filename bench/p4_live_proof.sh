#!/bin/bash
# Live-path proof for the P4 multicore RX steering distributor on .165:
# launch r2dp-fwd --dp p4 live (NO bench) with R2DP_P4_WORKERS=N, install an
# outbound SA + /32,/32 udp PROTECT, inject clear IPv4/UDP on the inner tap,
# and confirm the dataplane counters MOVE (rx in / ESP out) -> the RX
# distributor hashed each frame to a slice and the per-slice worker
# pipeline+extern forwarded it.  Requires root taps.
#   p4_live_proof.sh WORKERS FRAMES
set -u
H=yescorp@192.168.0.165
B=/home/yescorp/r2dp-p4
W="${1:-2}"; FRAMES="${2:-80000}"
KEY=00112233445566778899aabbccddeeff00112233
run() { ssh -o ConnectTimeout=25 "$H" "$@"; }

run "pgrep -f \"r2dp-fwd --dp p4.*file-prefix r2q.*$W\" | xargs -r sudo -n kill -9 2>/dev/null; \
     sudo -n rm -f /tmp/lp.sock; sudo -n rm -rf /run/user/0/dpdk/r2q; \
     sudo -n ip link del r2po 2>/dev/null; sudo -n ip link del r2pi 2>/dev/null; sleep 1; \
     LOG=/tmp/livep.log; : > \$LOG; cd $B; \
     sudo -n env R2DP_P4_WORKERS=$W R2DP_P4_SPEC=$B/p4/r2dp.out \
       R2DP_P4_SCRATCH=$B/scratch R2DP_SWX_SRC=/home/yescorp/dpdk-src \
       nohup ./build/fwd/r2dp-fwd --dp p4 -s /tmp/lp.sock \
       --vdev=net_tap0,iface=r2po --vdev=net_tap1,iface=r2pi \
       --vdev=crypto_openssl0,max_nb_queue_pairs=$W --no-huge --no-pci -m 1024 \
       --file-prefix r2q > \$LOG 2>&1 & echo \$! > /tmp/lp.pid; sleep 8; cd $B/build; \
     sudo -n env R2DP_SOCK=/tmp/lp.sock ./r2dpctl /tmp/lp.sock sa-add dir=out spi=0x2001 \
       src=192.0.2.1 dst=203.0.113.1 enc=aes-gcm-16 key=$KEY >/dev/null 2>&1; \
     sudo -n env R2DP_SOCK=/tmp/lp.sock ./r2dpctl /tmp/lp.sock sp-add dir=out action=protect \
       src=10.0.0.1/32 dst=10.0.0.2/32 proto=udp \
       tsrc=192.0.2.1 tdst=203.0.113.1; sleep 2"
echo "=== launch+SA/SP done, forwarder running? ==="
run "sudo -n pgrep -x r2dp-fwd; sudo -n grep -iE 'slices|distributor|BIND|SA add|crypto.*ready|I/O:' /tmp/livep.log | head"

cat > /tmp/p4_live_inj.py <<PYEOF
import socket, struct, time, sys
LOG="/tmp/livep.log"; TOTAL=int(sys.argv[1])
i=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); i.bind(("r2pi",0))
ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+8,0,0,64,17,0,socket.inet_aton("10.0.0.1"),socket.inet_aton("10.0.0.2"))
ud=struct.pack("!HHHH",1024,9,8,0)
f=bytes.fromhex("0200010203040200000000010800")+ip+ud+bytes(16)
time.sleep(1.2)
def counters():
    d=open(LOG).read()
    # p4 worker dump: 'pkt: out_rx=... in_rx=... out0=...' plus per-slice c_outer per line
    import re
    out0=0; outer=0
    for m in re.finditer(r"pkt:\s*out_rx=\S+ in_rx=(\S+) out0=(\S+)", d):
        outer=int(m.group(1)); out0=int(m.group(2))
    return outer, out0
s0=counters(); t0=time.time()
for _ in range(TOTAL): i.send(f)
time.sleep(2.0); s1=counters()
print("counters before:",s0," after:",s1)
print("delta outer_rx=%d esp_out0=%d"%(s1[0]-s0[0], s1[1]-s0[1]))
PYEOF
scp -q /tmp/p4_live_inj.py "$H":/home/yescorp/r2dp-p4/liveinj.py
run "cd $B && sudo -n python3 liveinj.py $FRAMES 2>&1"
echo "=== crypto enq/deq (per slice) from periodic dump ==="
run "sudo -n grep -iE 'crypto:|\| ipsec|pkt:' /tmp/livep.log | tail -6"

echo "=== delete-proof per shard: sp-del then re-inject -> a6(PROTECT)->a7(BYPASS) on EVERY slice ==="
run "cd /home/yescorp/r2dp-p4/build; \
     sudo -n env R2DP_SOCK=/tmp/lp.sock ./r2dpctl /tmp/lp.sock sp-del dir=out \
       src=10.0.0.1/32 dst=10.0.0.2/32 proto=udp \
       tsrc=192.0.2.1 tdst=203.0.113.1; sleep 1"
run "sudo -n grep -nE 'sp_del|outbound entry del|BIND removed|a6=|a7=' /tmp/livep.log | tail -8"

# re-inject after delete so the per-slice outbound miss (a7/bypass) is counted
cat > /tmp/p4_live_del.py <<PYEOF
import socket, struct, time, sys
LOG="/tmp/livep.log"; TOTAL=int(sys.argv[1])
i=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); i.bind(("r2pi",0))
ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+8,0,0,64,17,0,socket.inet_aton("10.0.0.1"),socket.inet_aton("10.0.0.2"))
ud=struct.pack("!HHHH",1024,9,8,0)
f=bytes.fromhex("0200010203040200000000010800")+ip+ud+bytes(16)
for _ in range(TOTAL): i.send(f)
time.sleep(2.0)
d=open(LOG).read()
print("a6/protect events in log after del:", d.count("a6="), " a7/bypass:", d.count("a7="))
PYEOF
scp -q /tmp/p4_live_del.py "$H":/home/yescorp/r2dp-p4/livedel.py
run "cd /home/yescorp/r2dp-p4 && sudo -n python3 livedel.py 30000 2>&1"
echo "=== post-delete per-slice action counters ==="
run "sudo -n grep -E 'pkt:' /tmp/livep.log | tail -4"
run "sudo -n kill -9 \$(cat /tmp/lp.pid) 2>/dev/null; rm -f /tmp/lp.pid"
echo done

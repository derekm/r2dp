#!/bin/bash
# p4_bench.sh -- side-by-side ESP-encrypt throughput for the r2dp P4 (SWX) and
# DPDK backends on .165.  Both run on ROOT net_tap transport (memif does not
# materialize on the P4 leg), one outbound SA + a /32,/32 udp PROTECT policy,
# and N clear IPv4/UDP frames injected on the inner tap (r2pi) from a raw
# AF_PACKET socket.  Rate is measured from the backend's own counter deltas
# (P4: 'pkt: in_rx=/out0='; DPDK: 'stats rx=/esp=') so it is the DATA PLANE
# accept/egress, not a packet sniff.
#
#   p4_bench.sh [p4|dpdk|both] [frames] [size]
#
# Requires: passwordless sudo + built forwarders + installed spec on .165.
# Measured 2026-11-07 (i5-6500T, 4 logic CPUs, tap, openssl PMD, 64B):
#   P4   ~131K pps (single pthread worker; dataplane is the bottleneck)
#   DPDK ~245K pps (2 lcores; tap/injector was the bottleneck at this load)
# => DPDK roughly 1.9x faster on this box.  Tune FRAMES/SIZE for a different
#    packet mix; the DPDK launch keeps -m 1024 because --no-huge needs a size.

set -u
H="yescorp@192.168.0.165"
B=/home/yescorp/r2dp-p4
DP="${1:-both}"
FRAMES="${2:-400000}"
SIZE="${3:-64}"
KEY=00112233445566778899aabbccddeeff00112233
run() { ssh -o ConnectTimeout=25 "$H" "$@"; }

launch() { # $1=p4|dpdk
  run "pgrep -x r2dp-fwd | xargs -r sudo -n kill -9 2>/dev/null; \
       sudo -n rm -rf /run/user/0/dpdk/r2p4 /tmp/r2dp-p4.sock; \
       sudo -n ip link del r2po 2>/dev/null; sudo -n ip link del r2pi 2>/dev/null; sleep 1; \
       cd $B; LOG=/tmp/p4b_$1.log; : >\"\$LOG\"; \
       if [ $1 = p4 ]; then
         sudo -n env R2DP_P4_SPEC=$B/p4/r2dp.out R2DP_P4_SCRATCH=$B/scratch \
           R2DP_SWX_SRC=/home/yescorp/dpdk-src \
           nohup ./build/fwd/r2dp-fwd --dp p4 -s /tmp/r2dp-p4.sock \
           --vdev=net_tap0,iface=r2po --vdev=net_tap1,iface=r2pi \
           --vdev=crypto_openssl0 --no-huge --no-pci --file-prefix r2p4 >\"\$LOG\" 2>&1 &
       else
         sudo -n nohup ./build/fwd/r2dp-fwd --dp dpdk -s /tmp/r2dp-p4.sock \
           -n 2 --vdev=net_tap0,iface=r2po --vdev=net_tap1,iface=r2pi \
           --vdev=crypto_openssl0 --no-huge -m 1024 --no-pci \
           --no-telemetry --file-prefix r2p4 >\"\$LOG\" 2>&1 &
       fi; sleep 7;
       cd $B/build; S(){ sudo -n env R2DP_SOCK=/tmp/r2dp-p4.sock ./r2dpctl /tmp/r2dp-p4.sock \"\$@\"; }; \
       S sa-add dir=out spi=0x2001 src=192.0.2.1 dst=203.0.113.1 enc=aes-gcm-16 key=$KEY >/dev/null 2>&1; \
       S sp-add dir=out action=protect src=10.0.0.1/32 dst=10.0.0.2/32 proto=udp tsrc=192.0.2.1 tdst=203.0.113.1; \
       sleep 1"
}

bench_one() { # $1=p4|dpdk
  local LOG=/tmp/p4b_$1.log; local RE
  [ $1 = p4 ] && RE="in_rx=([0-9]+).*out0=([0-9]+)" || RE="stats rx=([0-9]+).*esp=([0-9]+)"
  cat > /tmp/p4_benchi.py <<PYEOF
import socket, struct, time, re, sys
LOG=sys.argv[1]; RE=sys.argv[2]; PAT=re.compile(RE)
i=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); i.bind(("r2pi",0))
ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+8,0,0,64,17,0,socket.inet_aton("10.0.0.1"),socket.inet_aton("10.0.0.2"))
ud=struct.pack("!HHHH",1024,9,8,0)
f=bytes.fromhex("0200010203040200000000010800")+ip+ud+bytes(16)
def snap():
    d=open(LOG).read(); m=list(PAT.finditer(d))
    if not m: return None
    g=m[-1].groups(); return (int(g[0]),int(g[1]))
time.sleep(1.2); TOTAL=$FRAMES; results=[]
for trial in range(5):
    s0=snap(); t0=time.time()
    for _ in range(TOTAL): i.send(f)
    el=time.time()-t0; time.sleep(0.9); s1=snap()
    if s0 and s1 and s1[0]>s0[0]:
        rx=s1[0]-s0[0]; results.append(rx/el)
        print("trial %d wall=%.3f rx_fps=%.0f"%(trial,el,rx/el),flush=True)
if results:
    results.sort(); print("MEDIAN_RX_FPS=%.0f"%results[len(results)//2],flush=True)
PYEOF
  chmod +x /tmp/p4_benchi.py
  scp -q /tmp/p4_benchi.py "$H":/home/yescorp/r2dp-p4/benchi.py
  run "cd $B && sudo -n python3 benchi.py $LOG \"$RE\" 2>&1"
}

for D in $DP; do
  [ "$D" = p4 ] || [ "$D" = dpdk ] || continue
  echo "========== $D backend =========="
  launch "$D"
  bench_one "$D"
done
echo "done"

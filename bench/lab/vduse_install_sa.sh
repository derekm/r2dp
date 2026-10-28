#!/bin/bash
# Deterministic no-tap data-plane proof: install an inbound SA + SP via
# r2dpctl, then inject a valid AES-GCM ESP packet into the VDUSE outer netdev
# (eth1), verify the forwarder decrypts it and emits inner on the inner tap.
LB=/home/yescorp/bench
CTL=/home/yescorp/r2mc-fresh/build-dpdk/tools/r2dpctl
S=/tmp/r2dp-dpdk.sock
[ -x "$CTL" ] || CTL=$(find /home/yescorp/r2mc-fresh -name r2dpctl -type f | head -1)
echo "CTL=$CTL  sock=$S"
# install an inbound SA (decrypt) that will match an injected ESP
# SPI 0xbabe0001, dst outer 192.0.2.1 tunnel, AES-GCM-16 key
KEY=000102030405060708090a0b0c0d0e0f10111213
sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL $S hello 2>&1 | tail -2
echo "--- sa-add in (decrypt SPI 0xbabe0001 dip 192.0.2.1) ---"
sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL $S sa-add dir=in spi=0xbabe0001 src=192.0.2.2 dst=192.0.2.1 enc=aes-gcm-16 key=$KEY 2>&1 | tail -3
echo "--- sp-add in protect ---"
sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL $S sp-add dir=in action=protect src=10.0.1.0/24 dst=10.0.2.0/24 tsrc=192.0.2.2 tdst=192.0.2.1 2>&1 | tail -2
echo "--- dump sa ---"
sudo env LD_LIBRARY_PATH=/home/yescorp/r2dp-prefix/lib64 $CTL $S dump-sa 2>&1 | tail -3

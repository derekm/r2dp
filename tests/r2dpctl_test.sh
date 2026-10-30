#!/usr/bin/env bash
# r2dpctl write commands against r2dp-mockfwd: hello, sa-add/sa-del,
# sp-add/sp-del (by slid and by selector), the dump round trip, and the
# exit-status contract (0 ok, 1 forwarder refused, 2 usage).
set -u
CTL=$1 MOCK=$2
T=$(mktemp -d "${TMPDIR:-/tmp}/r2dpctl.XXXXXX")
S=$T/s.sock
"$MOCK" -s "$S" 2>"$T/mock.log" & MP=$!
trap 'kill $MP 2>/dev/null; wait $MP 2>/dev/null; rm -rf "$T"' EXIT
for _ in $(seq 50); do [ -S "$S" ] && break; sleep 0.1; done
fails=0
ok()   { if "$@" >"$T/out" 2>&1; then echo "ok   $*"; else echo "FAIL $* (rc=$?)"; cat "$T/out"; fails=$((fails+1)); fi; }
rc()   { local want=$1; shift; "$@" >"$T/out" 2>&1; local r=$?
         if [ $r = "$want" ]; then echo "ok   rc=$want: $*"; else echo "FAIL rc=$r want $want: $*"; cat "$T/out"; fails=$((fails+1)); fi; }
has()  { if grep -qF -- "$1" "$T/out"; then echo "ok   output has: $1"; else echo "FAIL output lacks: $1"; cat "$T/out"; fails=$((fails+1)); fi; }
C="$CTL $S"
KEY=000102030405060708090a0b0c0d0e0f10111213

ok $C hello;                                       has "version=2"
ok $C sa-add dir=out spi=0x1001 src=192.0.2.1 dst=192.0.2.2 enc=aes-gcm-16 key=$KEY reqid=5
rc 1 $C sa-add dir=out spi=0x1001 src=192.0.2.1 dst=192.0.2.2 enc=aes-gcm-16 key=$KEY
ok $C sa-add dir=in spi=0x2001 src=192.0.2.2 dst=192.0.2.1 enc=aes-cbc integ=sha256 \
      key=000102030405060708090a0b0c0d0e0f authkey=000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f wsize=128
ok $C sp-add dir=out action=protect src=10.0.1.0/24 dst=10.0.2.0/24 proto=tcp dport=22 tsrc=192.0.2.1 tdst=192.0.2.2 slid=7
ok $C sp-add dir=out action=discard src=10.0.1.5/32 dst=10.0.2.0/24 slid=8
ok $C dump-sp;  has "slid=7 10.0.1.0/24:0->10.0.2.0/24:22 proto=6";  has "slid=8"
ok $C sp-del slid=7
ok $C sp-del dir=out src=10.0.1.5/32 dst=10.0.2.0/24
ok $C dump-sp;  has "0 SP(s)"
ok $C sa-del spi=0x1001 dst=192.0.2.2
rc 1 $C sa-del spi=0x1001 dst=192.0.2.2
ok $C sa-del spi=0x2001 dst=192.0.2.1
rc 2 $C sa-add spi=1
rc 2 $C sa-add dir=in spi=0x3001 src=192.0.2.2 dst=192.0.2.1 enc=aes-gcm-16 key=$KEY wsize=1025
rc 2 $C sa-add spi=0x1001 dst=192.0.2.2 src=192.0.2.1 enc=aes-gcm-16 key=$KEY   # no dir (v2)
rc 2 $C sp-add dir=out action=protect src=10.0.0.0/8 dst=10.0.0.0/8             # no tunnel
rc 2 $C bogus
[ $fails = 0 ] && echo "r2dpctl_test: OK" || echo "r2dpctl_test: $fails failures"
exit $((fails != 0))

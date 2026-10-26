#!/bin/sh
# r2dpctl <-> mock: shell-level smoke test.  args: <r2dp-mockfwd> <r2dpctl>
set -eu
MOCK="$1"; CTL="$2"; D=$(mktemp -d); S="$D/s"
"$MOCK" -s "$S" -K & P=$!
trap 'kill $P 2>/dev/null; rm -rf "$D"' EXIT
for i in 1 2 3 4 5 6 7 8 9 10; do [ -S "$S" ] && break; sleep 0.1; done
c() { "$CTL" -s "$S" "$@"; }
c hello | grep -q "gcm16=1"
c sa-add --spi 0x1000 --src 192.0.2.2 --dst 192.0.2.1 --key 000102030405060708090a0b0c0d0e0f10111213 --esn | grep -q "sa-add: ok"
c sa-add --spi 0x1000 --src 192.0.2.2 --dst 192.0.2.1 --key 000102030405060708090a0b0c0d0e0f10111213 2>&1 | grep -q "File exists"
c sa-del --spi 0x1000 --dst 192.0.2.1 | grep -q "sa-del: ok"
c sa-del --spi 0x1000 --dst 192.0.2.1 2>&1 | grep -q "No such file"
c sp-add --dir out --src 10.2.0.0/24 --dst 10.1.0.0/24 --action protect --tun-src 192.0.2.1 --tun-dst 192.0.2.2 | grep -q "slid=1"
c sp-add --dir out --src 10.2.0.0/24 --dst 10.1.0.0/24 --action protect --tun-src 192.0.2.1 --tun-dst 192.0.2.2 2>&1 | grep -q "File exists"
c sp-add --dir in --src 10.1.0.0/24 --dst 10.2.0.0/24 --action protect --tun-src 192.0.2.2 --tun-dst 192.0.2.1 | grep -q "slid=2"
c sp-dump | grep -q "slid=2 dir=1 10.1.0.0/24"
c sp-del --slid 1 | grep -q "sp-del: ok"
[ "$(c sp-dump | wc -l)" = 1 ]
echo "ctl_test ok"

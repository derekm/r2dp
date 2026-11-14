#!/bin/sh
# Build the pinned, patched DPDK that the P4/SWX backend's full feature set
# needs (COMMITS C2), reproducibly from this repository:
#
#   contrib/upstream/build-dpdk-p4.sh [PREFIX]      (default ./dpdk-p4)
#   PKG_CONFIG_PATH=PREFIX/lib/pkgconfig meson setup build -Denable_p4=enabled
#
# Fetches DPDK $DPDK_VER from fast.dpdk.org, checks it against the pinned
# SHA-256, applies the extern patch series below and installs a minimal
# build (the drivers the forwarder, tests and benches use).  Stock DPDK
# still builds -Denable_p4 with reduced features: meson detects the patched
# fields and the backend refuses SAs it could not enforce (see README.md).
#
# Series (order matters; 0003 is folded into 0004, which is cumulative):
#   0004-rte_swx_ipsec-natt.patch        partial-batch flush + NAT-T
#   0005-rte_ipsec-replay-window.patch   anti-replay window plumbing + fix
set -eu

DPDK_VER=${DPDK_VER:-24.11}
DPDK_SHA256=${DPDK_SHA256:-0b1abc1fda430192ac7eb2ac9f8d83f268a32cd1bb7995b1d6ee8009c67f8f8f}
SERIES="0004-rte_swx_ipsec-natt.patch 0005-rte_ipsec-replay-window.patch"
DRIVERS=bus/vdev,mempool/ring,mempool/stack,net/memif,net/tap,net/null,net/ring,crypto/openssl,crypto/null

HERE=$(cd "$(dirname "$0")" && pwd)
PREFIX=$(mkdir -p "${1:-dpdk-p4}" && cd "${1:-dpdk-p4}" && pwd)
WORK=${WORK:-$(mktemp -d)}

tarball="$WORK/dpdk-$DPDK_VER.tar.xz"
[ -f "$tarball" ] || curl -fsSL -o "$tarball" \
	"https://fast.dpdk.org/rel/dpdk-$DPDK_VER.tar.xz"
echo "$DPDK_SHA256  $tarball" | sha256sum -c -

src="$WORK/dpdk-$DPDK_VER"
rm -rf "$src"
tar -C "$WORK" -xf "$tarball"
for p in $SERIES; do
	echo "== applying $p"
	patch -d "$src" -p1 --forward --batch < "$HERE/$p"
done

# no libnuma headers: build for one NUMA node rather than fail
numa=
[ -f /usr/include/numa.h ] || numa=-Dmax_numa_nodes=1
meson setup "$src/build" "$src" --prefix="$PREFIX" --libdir=lib \
	--buildtype=release -Dtests=false -Denable_docs=false \
	-Ddisable_apps='*' -Denable_drivers="$DRIVERS" -Dplatform=generic \
	$numa ${DPDK_MESON_ARGS:-}
ninja -C "$src/build" install >/dev/null
# The P4 backend compiles its SWX pipeline at start-up, and that code
# includes lib/pipeline's internal headers, which DPDK does not install:
# keep them beside the install (r2dp's meson points R2DP_SWX_SRC here).
mkdir -p "$PREFIX/share/dpdk-swx-src/lib/pipeline"
cp "$src"/lib/pipeline/*.h "$PREFIX/share/dpdk-swx-src/lib/pipeline/"
printf '%s\n' "$DPDK_VER+r2dp-p4" > "$PREFIX/R2DP_DPDK_VERSION"
echo "installed: PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig LD_LIBRARY_PATH=$PREFIX/lib"

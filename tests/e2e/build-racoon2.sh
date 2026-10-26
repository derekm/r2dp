#!/bin/bash
# Build racoon2 with the r2dp backend in a scratch dir (your checkout is not touched):
# clean clone of <racoon2-src> HEAD -> apply patches/racoon2-r2dp-backend.patch ->
# autoreconf -> configure --with-km-backend=r2dp -> make -> make install.
#   build-racoon2.sh <racoon2-src> <workdir> <r2dp-prefix>     installs into <workdir>/r2inst
set -eu
SRC="${1:?racoon2 git checkout}"; W="${2:?workdir}"; PFX="${3:?r2dp install prefix}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH="$HERE/../../patches/racoon2-r2dp-backend.patch"
rm -rf "$W/src" "$W/rbuild" "$W/r2inst"; mkdir -p "$W"
git clone -q --local "$SRC" "$W/src"
echo "==> racoon2 base: $(git -C "$W/src" log --oneline -1)"
git -C "$W/src" apply "$PATCH"
( cd "$W/src" && autoreconf -fi >"$W/autoreconf.log" 2>&1 ) || { tail "$W/autoreconf.log"; exit 1; }
mkdir "$W/rbuild"; cd "$W/rbuild"
"$W/src/configure" --with-km-backend=r2dp --with-r2dp="$PFX" --disable-kinkd \
	--prefix="$W/r2inst" >"$W/configure.log" 2>&1 || { tail "$W/configure.log"; exit 1; }
make -j"$(nproc)" >"$W/make.log" 2>&1 || { grep -E "error" "$W/make.log" | head; exit 1; }
# Out-of-tree `make install` of upstream currently trips over a hook script
# ('01setkey') late in install-exec-hook; binaries/libs are already in place.
make install >"$W/install.log" 2>&1 || echo "(note: make install exited non-zero late in the hook step; checking binaries)"
for b in iked spmd ikedctl; do [ -x "$W/r2inst/sbin/$b" ] || { echo "missing $b"; exit 1; }; done
echo "==> built: $W/r2inst/sbin/{iked,spmd,ikedctl} (r2dp backend)"

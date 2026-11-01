#!/bin/bash
# Reproducible r2dp benchmark sweep: build, record the environment, run
# fwd_bench (single-core data-path cost) and e2e_bench (two forwarders over
# memif), write JSON/CSV and a summary table.  See bench/README.md.
#
#   bench/run.sh [--quick] [--no-build] [--no-e2e] [--no-fwd]
#
# Knobs (environment):
#   BUILD=build-bench        meson build dir (configured release + DPDK)
#   OUT=bench/results/<utc>  result directory
#   SIZES=64,512,1400        fwd_bench inner sizes   E2E_SIZES=64,512,1400 frame sizes
#   TUNNELS=1,65,201         fwd_bench tunnel counts E2E_TUNNELS=1,1000
#   WORKERS=1                fwd_bench worker lcores E2E_WORKERS=1,2
#   RUNS=5 SECS=2 LOSS=0.001 PMD=auto|aesni_mb|openssl  HUGE=auto|0|1
#   CPUS="0-7"               CPUs the sweep may use (default: all online)
set -eu
cd "$(dirname "$0")/.."
QUICK=0 BUILDIT=1 E2E=1 FWD=1
for a in "$@"; do case $a in
	--quick) QUICK=1 ;; --no-build) BUILDIT=0 ;; --no-e2e) E2E=0 ;; --no-fwd) FWD=0 ;;
	-h|--help) sed -n '2,17p' "$0"; exit 0 ;;
	*) echo "unknown option $a"; exit 2 ;;
esac; done
if [ $QUICK = 1 ]; then
	: "${SIZES:=64,1400}" "${TUNNELS:=1,65}" "${RUNS:=3}" "${E2E_SIZES:=512}"
	: "${E2E_TUNNELS:=1,100}" "${E2E_WORKERS:=1}" "${SECS:=1}"
fi
BUILD=${BUILD:-build-bench}; SIZES=${SIZES:-64,512,1400}; TUNNELS=${TUNNELS:-1,65,201}
WORKERS=${WORKERS:-1}; RUNS=${RUNS:-5}; SECS=${SECS:-2}; LOSS=${LOSS:-0.001}
E2E_SIZES=${E2E_SIZES:-64,512,1400}; E2E_TUNNELS=${E2E_TUNNELS:-1,1000}
E2E_WORKERS=${E2E_WORKERS:-1,2}; PMD=${PMD:-auto}; HUGE=${HUGE:-auto}
OUT=${OUT:-bench/results/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT"

# ---- build ----
if [ $BUILDIT = 1 ]; then
	[ -f "$BUILD/build.ninja" ] ||
	    meson setup "$BUILD" -Dbuildtype=release -Denable_dpdk=enabled >"$OUT/build.log" 2>&1 ||
	    { echo "meson setup failed (DPDK >= 22.11 dev files + pkg-config needed), see $OUT/build.log"; exit 1; }
	ninja -C "$BUILD" >>"$OUT/build.log" 2>&1 || { echo "build failed, see $OUT/build.log"; exit 1; }
fi
[ -x "$BUILD/bench/fwd_bench" ] || { echo "$BUILD/bench/fwd_bench missing (DPDK not found at configure?)"; exit 1; }

# ---- environment ----
CPUS=${CPUS:-$(cat /sys/devices/system/cpu/online)}
cpulist() { local r=() p a b; for p in ${1//,/ }; do a=${p%-*}; b=${p#*-}; r+=($(seq "$a" "$b")); done; echo "${r[@]}"; }
CL=($(cpulist "$CPUS")); NCPU=${#CL[@]}
HPF=$(awk '/HugePages_Free/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
HPS=$(awk '/Hugepagesize/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
if [ "$HUGE" = auto ]; then
	# e2e: 3 processes x 1 GB; fall back to --no-huge (slower, still valid)
	HUGE=0; [ $((HPF * HPS)) -ge $((3 * 1024 * 1024 + 512 * 1024)) ] && HUGE=1
fi
PMDDIR=$(pkg-config --variable=pmdsdir libdpdk 2>/dev/null || true)
[ -n "$PMDDIR" ] || PMDDIR=$(ls -d "$(pkg-config --variable=libdir libdpdk 2>/dev/null)"/dpdk/pmds-* 2>/dev/null | head -1)
HAVE_MB=0; ls "$PMDDIR"/librte_crypto_ipsec_mb.so* >/dev/null 2>&1 && HAVE_MB=1
if [ "$PMD" = auto ]; then PMD=openssl; [ $HAVE_MB = 1 ] && PMD=aesni_mb; fi
GIT=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
DIRTY=$(git status --porcelain --untracked-files=no 2>/dev/null | grep -q . && echo True || echo False)
MODEL=$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)
FLAGS=$(grep -m1 -o -w -E 'aes|avx2|avx512f|vaes|vpclmulqdq' /proc/cpuinfo | sort -u | tr '\n' ' ')
GOV=$(cat /sys/devices/system/cpu/cpu${CL[0]}/cpufreq/scaling_governor 2>/dev/null || echo n/a)
python3 - "$OUT/env.json" <<PY
import json, sys
json.dump({"git": "$GIT", "dirty": $DIRTY, "cpu_model": """$MODEL""",
  "cpu_flags": "$FLAGS".split(), "cpus_used": "$CPUS", "ncpu": $NCPU,
  "governor": "$GOV", "kernel": "$(uname -sr)",
  "dpdk": "$(pkg-config --modversion libdpdk 2>/dev/null || echo unknown)",
  "compiler": "$(cc --version | head -1)", "pmd": "$PMD",
  "hugepages": $HUGE, "hugepages_free": $HPF, "hugepage_kb": $HPS,
  "date_utc": "$(date -u +%FT%TZ)"}, open(sys.argv[1], "w"), indent=1)
PY
echo "r2dp bench: git $GIT, $MODEL, $NCPU CPUs, DPDK $(pkg-config --modversion libdpdk 2>/dev/null), PMD $PMD, hugepages=$HUGE -> $OUT"

# ---- fwd_bench ----
if [ $FWD = 1 ]; then
	for w in ${WORKERS//,/ }; do
		[ "$w" -le "$NCPU" ] || { echo "skip fwd_bench workers=$w (> $NCPU CPUs)"; continue; }
		WA=(); [ "$w" -gt 1 ] && WA=(--workers "$w")
		taskset -c "$CPUS" "$BUILD/bench/fwd_bench" --runs "$RUNS" --sizes "$SIZES" \
		    --tunnels "$TUNNELS" --pmd "$PMD" "${WA[@]}" --json "$OUT/fwd_w$w.json" \
		    >"$OUT/fwd_w$w.log" 2>&1 || { echo "fwd_bench failed, see $OUT/fwd_w$w.log"; exit 1; }
	done
fi

# ---- e2e_bench ----
if [ $E2E = 1 ]; then
	: >"$OUT/e2e.jsonl"
	for w in ${E2E_WORKERS//,/ }; do
		per=$(( w > 1 ? w + 1 : 1 ))         # workers (+ dispatcher) per forwarder
		need=$(( 2 + 2 * per ))              # tgen tx/rx, A, B (+ control, may share)
		[ "$need" -le "$NCPU" ] || { echo "skip e2e workers=$w (needs $need CPUs, have $NCPU)"; continue; }
		# CPUs in order: tgen tx,rx | A workers(+dispatcher) | B ... | control
		sl() { local IFS=,; echo "${CL[*]:$1:$2}"; }
		TGC=$(sl 0 2); AC=$(sl 2 $per); BC=$(sl $((2 + per)) $per); MC=${CL[$((2 + 2 * per))]:-}
		[ -n "$MC" ] || { MC=${CL[$((NCPU - 1))]}; echo "  note: workers=$w: control threads share CPU $MC (zero-loss rates pessimistic)"; }
		for t in ${E2E_TUNNELS//,/ }; do
			echo "e2e: workers=$w tunnels=$t sizes=$E2E_SIZES"
			W=$w NTUN=$t SIZES=$E2E_SIZES SECS=$SECS LOSS=$LOSS PMD=$PMD HUGE=$HUGE \
			    TG_CPUS=$TGC A_CPUS=$AC B_CPUS=$BC MAIN_CPUS=$MC \
			    bench/e2e_bench.sh "$BUILD" >"$OUT/e2e_w${w}_t$t.log" 2>&1 ||
			    { echo "  failed, see $OUT/e2e_w${w}_t$t.log"; continue; }
			grep '^{' "$OUT/e2e_w${w}_t$t.log" >>"$OUT/e2e.jsonl" || true
		done
	done
fi

# ---- summary ----
python3 bench/summarize.py "$OUT"

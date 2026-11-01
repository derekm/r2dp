# Data-path benchmark / regression gate (DPDK builds only).  Run with
#   meson test -C BUILD --benchmark --print-errorlogs
# or directly: BUILD/bench/fwd_bench [--check] [SIZE]
if dpdk.found()
  fwd_bench = executable('fwd_bench', 'fwd_bench.c',
    '../fwd/dpdk_sad.c', '../fwd/dpdk_spd.c', '../fwd/dpdk_esp.c',
      '../fwd/dpdk_stats.c', '../fwd/dp_gcm.c', '../fwd/dp_nh.c', '../fwd/dpdk_nh.c', '../fwd/dp_sel.c',
    include_directories: [include_directories('../fwd'), r2dp_inc],
    dependencies: dpdk,
    link_with: libr2dp,
    c_args: ['-DR2DP_HAVE_DPDK=1'])
  benchmark('fwd_bench', fwd_bench, args: ['--check'], timeout: 300)
endif

# End-to-end forwarder benchmark: traffic generator + validating sink
# (bench/e2e_bench.sh drives it against two r2dp-fwd instances over memif).
if dpdk.found()
  e2e_tgen = executable('e2e_tgen', 'e2e_tgen.c', dependencies: dpdk)
endif

# Reproducible sweep (build dir = this one): `meson compile -C BUILD bench`
# or bench/run.sh directly; see bench/README.md.
run_target('bench', command: [find_program('run.sh'), '--no-build'],
  env: {'BUILD': meson.project_build_root()})

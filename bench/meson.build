# Data-path benchmark / regression gate (DPDK builds only).  Run with
#   meson test -C BUILD --benchmark --print-errorlogs
# or directly: BUILD/bench/fwd_bench [--check] [SIZE]
if dpdk.found()
  fwd_bench = executable('fwd_bench', 'fwd_bench.c',
    '../fwd/dp_gcm.c', '../fwd/dp_nh.c', '../fwd/dp_sel.c',
    include_directories: [include_directories('../fwd'), r2dp_inc],
    dependencies: dpdk,
    link_with: libr2dp,
    c_args: ['-DR2DP_HAVE_DPDK=1'])
  benchmark('fwd_bench', fwd_bench, args: ['--check'], timeout: 300)
endif

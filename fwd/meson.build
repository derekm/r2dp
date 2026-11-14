# fwd/ -- the r2dp forwarder.
#
# r2dp-fwd serves the r2dp control-plane socket.  Without DPDK it runs
# control-only (protocol-faithful, no forwarding); with DPDK (fwd_dp_dpdk)
# it also carries traffic.  DPDK is optional: the meson option --enable-dpdk
# turns on the DPDK dataplane build.
fs = import('fs')

# include_type system: DPDK's own headers are not ours to keep warning-clean
# (23.11 trips -Wpedantic), so they must not break -Dwerror=true builds.
dpdk = dependency('libdpdk', required: get_option('enable_dpdk'),
  version: '>=23.11', method: 'pkg-config', include_type: 'system')

fwd_sources = files(
  'ctl.c',
  'dp.c',
  'dp_sel.c',
  'dp_xfrm.c',
  'main.c',
)

fwd_o = fwd_sources
p4 = disabler()
if dpdk.found()
  fwd_o += files('dp_dpdk.c', 'dpdk_sad.c', 'dpdk_spd.c', 'dpdk_esp.c',
    'dpdk_stats.c', 'dp_gcm.c', 'dp_nh.c', 'dpdk_nh.c', 'dpdk_port.c')
  dpdk_inc = dpdk
else
  # When DPDK is disabled, dp_dpdk.c is not compiled; dp.h's
  # fwd_dp_dpdk_probe is provided by a stub in dp.c.
  dpdk_inc = []
endif

# P4/SWX backend: needs the DPDK SWX pipeline (librte_pipeline bundles the
# rte_swx_* codegen/ctl/ipsec in 24.11) + a compiled p4/r2dp.out spec.
if dpdk.found() and get_option('enable_p4').enabled()
  fwd_o += files('dp_p4.c')
  p4_inc = dpdk
else
  p4_inc = []
endif

r2dp_fwd = executable('r2dp-fwd',
  fwd_o,
  include_directories: [include_directories('.'), include_directories('../include')],
  dependencies: [dpdk_inc, p4_inc],
  link_with: libr2dp,
  install: false,
  c_args: (dpdk.found() ? ['-DR2DP_HAVE_DPDK=1'] : []) +
    (get_option('enable_p4').enabled() ?
      ['-DR2DP_HAVE_P4=1', '-DALLOW_EXPERIMENTAL_API'] : []) +
    ['-DDP_MAX_WK=' + get_option('dp_max_wk').to_string()],
)

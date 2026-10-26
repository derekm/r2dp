# DPDK forwarder: only built from M1 on, when libdpdk is required and found.
if ms >= 1 and dpdk.found()
  fwd_exe = executable('r2dp-fwd', 'fwd.c',
    dependencies: [dpdk, r2dp_dep], install: true)
endif

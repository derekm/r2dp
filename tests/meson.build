mockfwd_path = r2dp_mockfwd.full_path()

test('test_proto',
  executable('test_proto', 'test_proto.c',
    include_directories: include_directories('../include'),
    link_with: libr2dp),
  is_parallel: false)

# test_mock and shim_contract both spawn r2dp-mockfwd on a temp socket.
test('test_mock',
  executable('test_mock', 'test_mock.c',
    include_directories: include_directories('../include'),
    link_with: libr2dp),
  args: mockfwd_path,
  is_parallel: false)

test('shim_contract',
  executable('shim_contract', 'shim_contract.c',
    include_directories: include_directories('../include'),
    link_with: libr2dp),
  args: mockfwd_path,
  is_parallel: false)

# smoke_fwd drives a LIVE r2dp-fwd (control plane) via libr2dp, not the mock.
# It spawns the r2dp-fwd binary itself (path passed as arg 1).
test('smoke_fwd',
  executable('smoke_fwd', 'smoke_fwd.c',
    include_directories: include_directories('../include'),
    link_with: libr2dp),
  args: r2dp_fwd.full_path(),
  is_parallel: false)

# gcm_kat: RFC 4106 ESP known-answer test for the DPDK dataplane (crypto_openssl
# vdev, no hugepages).  Only when DPDK is built.  SKIP (77) on a lane that has
# DPDK but no crypto_openssl/EAL must be treated as a failure (see KAT header).
if dpdk.found()
  test('gcm_kat',
    executable('gcm_kat', 'gcm_kat.c', '../fwd/dp_gcm.c',
      include_directories: [include_directories('../include'),
                            include_directories('../fwd')],
      dependencies: [dpdk, dependency('libcrypto')],
      c_args: ['-DR2DP_HAVE_DPDK=1']),
    is_parallel: false, timeout: 60)

  # dp_sa: production dp_dpdk.c SA table under ASan/UBSan -- C1 (no
  # sa_tab[-1] write on a fresh inbound install) and newest-SA egress pick.
  test('dp_sa',
    executable('dp_sa', 'dp_sa.c', '../fwd/dp_gcm.c',
      include_directories: [include_directories('../include'),
                            include_directories('../fwd')],
      dependencies: dpdk,
      link_with: libr2dp,
      c_args: ['-DR2DP_HAVE_DPDK=1']),
    is_parallel: false, timeout: 60)
endif

# ctl_poll: regression for the accept/poll desync in fwd_ctl_run (0bb71e1):
# an idle just-accepted client must never stall the control loop.
test('ctl_poll',
  executable('ctl_poll', 'ctl_poll.c',
    include_directories: include_directories('../include'),
    link_with: libr2dp),
  args: r2dp_fwd.full_path(),
  is_parallel: false, timeout: 60)

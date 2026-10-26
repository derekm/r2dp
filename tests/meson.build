test('proto', executable('test_proto', 'test_proto.c', dependencies: r2dp_dep))

test_mock = executable('test_mock', 'test_mock.c', dependencies: r2dp_dep)
test('mockfwd-roundtrip', test_mock, args: [mockfwd_exe], depends: [mockfwd_exe],
     timeout: 30)

# Kernel-XFRM reference backend: translation checked against `ip xfrm` (root + netns; skips otherwise).
if is_variable('kfwd_exe')
  test('kfwd-xfrm', find_program('bash'), args: [files('kfwd_test.sh'), kfwd_exe, r2dpctl_exe],
       depends: [kfwd_exe, r2dpctl_exe], timeout: 120, suite: ['e2e'])
endif

# Shim contract test: needs a racoon2 checkout for its headers (-Dracoon2_src=...).
r2src = get_option('racoon2_src')
if r2src != ''
  r2lib = include_directories(r2src / 'lib', is_system: true)
  shim = static_library('r2dp_shim', '../shim/if_r2dp.c',
    include_directories: [inc, r2lib], dependencies: r2dp_dep)
  test('shim-contract',
       executable('shim_contract', 'shim_contract.c',
                  include_directories: [inc, r2lib],
                  link_with: shim, dependencies: r2dp_dep),
       args: [mockfwd_exe], depends: [mockfwd_exe], timeout: 30)
else
  message('racoon2_src not set: skipping shim contract test')
endif

test('r2dpctl-vs-mock', find_program('sh'), args: [files('ctl_test.sh'), mockfwd_exe, r2dpctl_exe],
     depends: [mockfwd_exe, r2dpctl_exe], timeout: 30)

# DPDK forwarder interop (milestone >= 1): root + netns + scapy; skips (77) otherwise.
if ms >= 1 and dpdk.found()
  test('fwd-interop', find_program('bash'),
       args: [files('e2e/fwd_e2e.sh'), fwd_exe, r2dpctl_exe],
       depends: [fwd_exe, r2dpctl_exe], timeout: 240, suite: ['e2e'])
  if get_option('racoon2_prefix') != ''
    test('iked-fwd-e2e', find_program('bash'),
         args: [files('e2e/ike_fwd_e2e.sh'), get_option('racoon2_prefix'), fwd_exe],
         depends: [fwd_exe], timeout: 240, suite: ['e2e'])
  endif
endif

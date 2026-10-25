project('r2dp', 'c',
  version: '0.1.0',
  license: 'MIT',
  meson_version: '>= 0.61',
  default_options: [
    'c_std=gnu11',
    'warning_level=3',
    'buildtype=debugoptimized',
  ])

# r2dp: external dataplane control protocol for racoon2.
#
# A PF_KEY-shaped wire contract over AF_UNIX SOCK_SEQPACKET that lets
# racoon2's iked/spmd drive an external forwarder instead of the kernel.
# This is the stand-alone library + mock forwarder + tests; the racoon2
# backend lives in racoon2 (lib/if_r2dp.c, see patches/).

subdir('libr2dp')

r2dp_inc = include_directories('include')

# Protocol-faithful forwarder with no dataplane (contract/dev tool).
r2dp_mockfwd = executable('r2dp-mockfwd',
  'tools/mockfwd.c',
  include_directories: r2dp_inc,
  link_with: libr2dp,
  install: false)

subdir('fwd')

subdir('tests')

# Install headers + pkg-config so racoon2's --with-r2dp=PREFIX can find it.
install_headers('include/r2dp/proto.h',
  'include/r2dp/client.h',
  subdir: 'r2dp')

pkg = import('pkgconfig')
pkg.generate(libr2dp,
  name: 'r2dp',
  description: 'r2dp control protocol library (external dataplane for racoon2)',
  version: meson.project_version(),
  libraries: libr2dp)

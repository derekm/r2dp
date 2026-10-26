libr2dp = static_library('r2dp', 'r2dp.c', 'cp.c',
  include_directories: inc, install: true)

r2dp_dep = declare_dependency(link_with: libr2dp, include_directories: inc)

install_headers('../include/r2dp/proto.h', '../include/r2dp/client.h', '../include/r2dp/cp.h',
                subdir: 'r2dp')

import('pkgconfig').generate(libr2dp,
  name: 'r2dp', description: 'r2dp control-protocol client/server library',
  subdirs: [])

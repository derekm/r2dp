project('r2dp', 'c',
  version: '0.1.0',
  meson_version: '>=0.57',
  default_options: ['c_std=gnu11', 'warning_level=2', 'buildtype=debugoptimized'])

fs  = import('fs')
ms  = get_option('milestone')
inc = include_directories('include')

add_project_arguments('-DR2DP_MILESTONE=@0@'.format(ms), '-D_GNU_SOURCE', language: 'c')

# M0 needs nothing but libc; DPDK is only required from M1 on.
dpdk = dependency('libdpdk', version: '>=' + get_option('dpdk_min'),
                  required: ms >= 1)

# Each component adds itself once its meson.build exists, so the tree
# configures cleanly at every stage of the plan.
foreach d : ['libr2dp', 'fwd', 'tools', 'tests']
  if fs.exists(d / 'meson.build')
    subdir(d)
  endif
endforeach

summary({'milestone': ms, 'DPDK': dpdk.found() ? dpdk.version() : 'not required/found'},
        section: 'r2dp')

# Kernel-XFRM reference backend: needs only linux/xfrm.h; liburing is optional (--io uring).
if cc.has_header('linux/xfrm.h')
  uring = dependency('liburing', required: false)
  kfwd_args = uring.found() ? ['-DHAVE_LIBURING'] : []
  kfwd_exe = executable('r2dp-kfwd', 'kfwd.c', 'xfrm.c',
    dependencies: [r2dp_dep, uring], c_args: kfwd_args, install: true)
  summary({'kfwd': 'built', 'kfwd io_uring': uring.found() ? 'yes (liburing ' + uring.version() + ')' : 'no'},
          section: 'r2dp')
endif

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

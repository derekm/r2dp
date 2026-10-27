# r2dp — external dataplane control protocol for racoon2

r2dp lets racoon2's IKE daemon (`iked`) and policy daemon (`spmd`) drive an
**external forwarder** — e.g. a standard DPDK IPsec app — instead of the kernel.
racoon2 only needs a small backend (`--with-km-backend=r2dp`); the forwarder is
a separate project that speaks a PF_KEY-shaped protocol over a unix socket.

    iked / spmd ──(rcpfk_* ABI)── if_r2dp.c ──(r2dp, SOCK_SEQPACKET)── forwarder (DPDK)

## Status
**M0 done** (protocol, client/server lib, mock forwarder, racoon2 backend, and a
real two-peer IKEv2 test). **M1 (the DPDK `r2dp-fwd` forwarder) in progress**:
the SAD + ESP decrypt pipeline is implemented and the data plane runs, but the
end-to-end "real ESP decrypts through the forwarder" proof and the iked-over-
veth interop exit gate are still open.
See `MILESTONES.md` for the full plan, exit gates, and findings.

## Layout
| path | what |
|---|---|
| `include/r2dp/proto.h` | the wire contract (algorithms = IANA IKEv2 IDs, protocols = IP proto numbers) |
| `include/r2dp/client.h`, `libr2dp/` | transport, validation, address helpers (client + server side) |
| `tools/mockfwd.c` | `r2dp-mockfwd`: protocol-faithful forwarder with no dataplane |
| `patches/racoon2-r2dp-backend.patch` | applies to racoon2 `93e3511` (pre-r2dp base): the r2dp backend, generated from derekm/racoon2 `feat/r2dp-km-backend` @ `baf7094` (`git diff 93e3511 baf7094`) |
| `tests/` | protocol/client: `test_proto`, `test_mock`, `shim_contract` (spin `r2dp-mockfwd`); control server: `ctl_unit`, `ctl_poll`, `smoke_fwd`; data plane (DPDK, crypto_openssl vdev): `gcm_kat`, `dp_sa`, `dp_path` (encrypt→decrypt round trip + policy dispositions); pure logic: `sel_test`, `nh_test` |
| `build.sh` | deps / check / build / test / sanitize / e2e / milestones |

## Quick start
    meson setup build && meson compile -C build && meson test -C build

Or via the helper script:
    ./build.sh deps -m 0                 # or: ./build.sh check -m 0
    ./build.sh test -m 0 --racoon2 /path/to/racoon2     # unit + contract tests
    sudo ./build.sh e2e --racoon2 /path/to/racoon2      # clean clone + patch + build + IKEv2 over veth

The racoon2 checkout passed to `--racoon2` is only read (the e2e flow works on a
scratch clone). Run the daemons against a forwarder with `R2DP_SOCK=<path>`
(default `/run/r2dp/r2dp.sock`) and optionally `R2DP_ROLE=iked|spmd`.

> If the scripts lost their executable bit (e.g. after a download/unzip):
> `chmod +x build.sh tests/e2e/*.sh`, or run them as `bash build.sh ...`.

## Provenance / reconstruction

This repo was stood up from the upstream prototype's `r2dp-claude.zip` (Telegram,
2026-10-24), which shipped `proto.h`, `mockfwd.c`, and the racoon2 backend
patch but **not** `client.h`, `libr2dp/`, or `tests/` (those were listed in
his README as empty dirs). The missing pieces were **reconstructed from the
`proto.h` contract and the `client.h` call-sites** in `shim/if_r2dp.c`
(racoon2 backend) and `tools/mockfwd.c`:

- `include/r2dp/client.h` — the full client/server API (connect/listen/accept,
  send/recv, hello/caps, message accessors, address helpers).
- `libr2dp/libr2dp.c` — transport + validation + address conversion.
- `meson.build` build system and the three M0 tests (`test_proto`,
  `test_mock`, `shim_contract`) with GitHub Actions CI (gcc + clang build/test,
  plus ASan/UBSan). See `ORIGIN.md` for the exact zip provenance.


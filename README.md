# r2dp — external dataplane control protocol for racoon2

r2dp lets racoon2's IKE daemon (`iked`) and policy daemon (`spmd`) drive an
**external forwarder** — e.g. a standard DPDK IPsec app — instead of the kernel.
racoon2 only needs a small backend (`--with-km-backend=r2dp`); the forwarder is
a separate project that speaks a PF_KEY-shaped protocol over a unix socket.

    iked / spmd ──(rcpfk_* ABI)── if_r2dp.c ──(r2dp, SOCK_SEQPACKET)── forwarder (DPDK)

## Status
**M0, M1 and M1.5 done** (M1.5 = kernel reference backend, only partly verifiable where it was written — see `docs/MILESTONES.md`): protocol, client/server lib, racoon2 backend, and a working
single-core DPDK forwarder (IPv4 ESP tunnel, AES-GCM) that real `iked`/`spmd`
drive end to end. **M2+ not started.** No performance numbers exist yet — all
testing ran on `--no-huge` virtual devices.
See `docs/MILESTONES.md` for the full plan, exit gates, and findings.

## Layout
| path | what |
|---|---|
| `include/r2dp/proto.h` | the wire contract (algorithms = IANA IKEv2 IDs, protocols = IP proto numbers) |
| `include/r2dp/client.h`, `libr2dp/` | transport, validation, address helpers (client + server side) |
| `libr2dp/cp.c`, `include/r2dp/cp.h` | control-plane engine shared by every forwarder (SAD/SPD semantics, hooks into the dataplane) |
| `fwd/fwd.c` | `r2dp-fwd`: the DPDK forwarder (needs `-m 1`) |
| `kfwd/` | `r2dp-kfwd`: reference backend that programs the **Linux kernel's XFRM** (netlink) behind the same protocol; `--io uring` is an experimental control loop (control plane only) |
| `tools/mockfwd.c` | `r2dp-mockfwd`: the control-plane engine with no dataplane |
| `tools/r2dpctl.c` | shell client: `hello`, `sa-add/del`, `sp-add/del/dump` |
| `shim/if_r2dp.c` | the racoon2 backend (single source of truth) |
| `patches/racoon2-r2dp-backend.patch` | applies to racoon2 `2fd758a`: 52 glue lines + `lib/if_r2dp.c` |
| `tests/` | `test_proto`, `test_mock`, `shim_contract`, `ctl_test.sh`, `kfwd_test.sh` (meson); `e2e/`: `ike_e2e.sh` (M0), `fwd_e2e.sh` + `fwd_peer.py` (scapy interop), `ike_fwd_e2e.sh` (iked + DPDK, both sides) — need root + netns |
| `build.sh` | deps / check / build / test / sanitize / e2e / milestones |

## Quick start
    ./build.sh deps -m 0                 # or: ./build.sh check -m 0
    ./build.sh test -m 0 --racoon2 /path/to/racoon2     # unit + contract tests
    sudo ./build.sh e2e --racoon2 /path/to/racoon2      # clean clone + patch + build + IKEv2 over veth
    sudo ./build.sh e2e -m 1 --racoon2 /path/to/racoon2 # ...plus the DPDK forwarder suites (needs DPDK >= 23.11)

Running the forwarder by hand (virtual devices, no hugepages):

    r2dp-fwd -l 0 --no-huge -m 256 --no-pci --vdev=net_af_packet0,iface=<black> \
      --vdev=net_af_packet1,iface=<red> --vdev=net_tap0,iface=r2tap0 --vdev=crypto_openssl0 -- \
      --sock /run/r2dp/r2dp.sock --local <tunnel-ip> --route <cidr>,black|red,<next-hop-mac> -v
    # give r2tap0 the tunnel IP (iked binds there); SIGUSR1 prints counters

The racoon2 checkout passed to `--racoon2` is only read (the e2e flow works on a
scratch clone). Run the daemons against a forwarder with `R2DP_SOCK=<path>`
(default `/run/r2dp/r2dp.sock`) and optionally `R2DP_ROLE=iked|spmd`.

> If the scripts lost their executable bit (e.g. after a download/unzip):
> `chmod +x build.sh tests/e2e/*.sh`, or run them as `bash build.sh ...`.

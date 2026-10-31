# r2dp coverage and evidence log

What is verified on `main`, by what, and where — and, as importantly, what
is **not**.  Modelled on the upstream prototype's milestone evidence log.
"CI" means it runs on every push (`.github/workflows/ci.yml`); "local"
means it has been run by hand and is not gated.  Update this file in the
same commit as the behaviour it describes.

## Verified

| Area | Evidence | Where | Gate |
|---|---|---|---|
| Wire protocol v2: framing, validation (lengths, key tail, flags) | `test_proto`, `test_mock` | `libr2dp/`, `tools/mockfwd.c` | CI |
| Shim-facing contract (ESN flag, NAT-T ports, AEAD key blob, unknown types) | `shim_contract` (libr2dp + mockfwd) | `tests/shim_contract.c` | CI |
| racoon2 backend ABI (`rcpfk_*` via `if_r2dp.c`: reqid, v2 dir, reconnect/epoch) | `r2dptest` in derekm/racoon2 `feat/r2dp-km-backend` | racoon2 `lib/r2dptest.c` | racoon2 `make check` |
| Control server: direction inference, reserved SPIs, prefixes, SP upsert, slow client | `ctl_unit`, `ctl_poll`, `smoke_fwd`, `sad_dump` | `fwd/ctl.c` | CI |
| Replay window >255 (`replay_win`, cap 1024, EINVAL above) | `ctl_unit` t_replay_win, `dp_sa`, `kfwd_test` | `fwd/ctl.c`, `fwd/dpdk_esp.c`, `fwd/dp_xfrm.c` | CI |
| Lifetimes: soft once with live counters (alloc > 0 so iked rekeys), hard leaves service before EXPIRE, soft+hard in one tick, byte limits, idle SA alloc 0 | `ctl_unit` t_expiry | `fwd/ctl.c` check_lifetimes | CI |
| AES-GCM-16 ESP (RFC 4106) known answers | `gcm_kat` | `fwd/dp_gcm.c` | CI |
| Anti-replay: every bit position, edges, windows 64/200/1024, ESN wrap, window 0 = off | `dp_sa` t_replay_window, t_wsize_install | `fwd/dpdk_esp.c` replay_accept | CI |
| SPD: rte_acl vs reference scan (random differential), binding/rekey, inbound per-SA policy, QSBR churn | `dp_sa`, `sel_test` | `fwd/dpdk_spd.c`, `fwd/dp_sel.c` | CI |
| Data path encrypt→decrypt, forged ICV/ciphertext, 8-bit length regression, batching | `dp_path` | `fwd/dpdk_esp.c` | CI |
| Stuck cryptodev: drop + count, quarantine, no enqueue behind it, recovery, no op/mbuf leak | `dp_path` (dequeue hook) | `fwd/dpdk_esp.c` crypto_run | CI |
| NAT-T demux (keepalive / IKE marker / ESP-in-UDP) | `dp_path` natt_class cases | `fwd/dpdk_esp.c` | CI |
| Interop with an independent ESP (scapy): round trips, pad lengths, TTL, window, replay, tamper, unknown SPI, selector, cleartext, truncation; **exact** drop counters | `tests/e2e/fwd_e2e.sh` phases positive/window/negative | DPDK and kernel backends | CI (unshare -Urnm) |
| NAT-T interop (RFC 3948): ESP-in-UDP round trips, egress framing, plain ESP to a NAT-T SA refused, keepalive consumed, IKE marker not ESP | `fwd_e2e.sh` phase natt | both backends | CI |
| Kernel XFRM backend via the r2dp socket | `kfwd_test`, `fwd_e2e.sh BACKEND=kernel` | `fwd/dp_xfrm.c` | CI |
| Multi-worker: each SA processed by its owner only; ESP sequence numbers unique and gapless per SPI under concurrency; inbound exactly-once; replay refused; non-owners count `steer` | `dp_mt` | `fwd/dpdk_esp.c`, `dp_owner` | CI |
| Multi-worker forwarding (dispatcher + 2/3 workers) with the same exact counters | `fwd_e2e.sh FWD_WORKERS=2,3` | `fwd/dp_dpdk.c` | CI |
| Sanitizers | all of the above under ASan+UBSan | — | CI |
| Data-path cost (cycles/pkt, Mpps; 64/512/1400B at 1/65/201 tunnels) | `bench/fwd_bench` regression gate | `bench/` | CI |

## Not covered (known gaps)

- **iked/spmd driving the forwarder end to end** (IKE_SA + CHILD_SA over
  veth, rekey under load) is not in CI; `build.sh e2e` needs root and a
  racoon2 build.  Soft-expiry rekey with zero loss has **not** been shown
  on `main` (the upstream prototype reported it for its own forwarder).
- **DPDK backend algorithms**: AES-GCM-16 only.  AES-CBC + HMAC, other
  GCM ICV lengths, CCM and ChaCha20 are kernel-backend only.
- **IPv6** (outer or inner) in the DPDK backend: not implemented.
- **Transport mode** in the DPDK backend: not implemented (tunnel only).
- **Multicore**: SA ownership, sequence uniqueness and replay under
  concurrent workers are tested (`dp_mt`, e2e with 2 and 3 workers), but
  there is no table-churn-under-load test and no TSan build; the
  dispatcher is software steering (no NIC RSS).  See MILESTONES M3.
- **Performance** numbers are cycles/pkt and Mpps of the ESP path on a
  `--no-huge` vdev (crypto_aesni_mb or crypto_openssl); no NIC, no
  line-rate or latency measurement, no dispatcher cost.
- **ESN with anti-replay off**: librte_ipsec still keeps a 64-packet
  window under ESN (it needs one to infer the high bits); the DPDK backend
  therefore cannot fully disable replay checking on an ESN SA.
- **Lifetime allocations**: the backends count bytes, not packets, so
  EXPIRE reports `cur_alloc` as 0/1 (idle/used), not a packet count.
- **Stuck cryptodev** recovery is exercised with a simulated device only.
- No fuzzing of the control socket or the packet parsers.
- No LICENSE file: the project's license has not been chosen.

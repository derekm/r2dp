# r2dp milestone map

Each milestone is gated by `-Dmilestone=N` (`./build.sh --milestone N`).
Every milestone has an exit gate that must pass before the next starts.
Deps listed are *added* at that milestone; earlier ones carry forward.

## M0 — Contract, client lib, mock forwarder, racoon2 shim  ✅ DONE
- **Built**: `include/r2dp/proto.h` (full wire contract, layout-asserted), `libr2dp/` (transport, validation, address helpers; client + server side), `tools/mockfwd.c` (`r2dp-mockfwd`: kernel-like in-memory SAD/SPD, no DPDK), `shim/if_r2dp.c` + `patches/racoon2-r2dp-backend.patch` (new racoon2 backend `--with-km-backend=r2dp --with-r2dp=PREFIX`).
- **Deps**: C compiler, meson, ninja, pkg-config. racoon2 build: autoconf/automake/libtool/bison/flex/libssl-dev/libpcap-dev. e2e: root, iproute2, iputils-ping.
- **Exit gate — met** (reproduce: `./build.sh e2e --racoon2 <racoon2 checkout>`; ~80 s):
  - `test_proto` (validation, address round-trips), `test_mock` (full SA/SP protocol incl. EEXIST/ENOENT, keys withheld by default), `shim_contract` (the real `rcpfk_*` API incl. `WAITREPLY` scratch routing, ESN/NAT-T/selector fidelity, refusals) — also clean under ASan/UBSan.
  - Patch applies cleanly to pristine upstream (`2fd758a`): 52 glue lines + one new 700-line file; `iked/` and `spmd/` untouched.
  - Two real racoon2 stacks (spmd+iked) in separate netns complete IKEv2 over a veth; each stack's forwarder received HELLO, SPD installs + `SP_DUMP`, forwarder-allocated `GETSPI`, and `SA_ADD`/`SA_UPDATE` for AES-GCM-16 ESP in tunnel mode with a tunnel SP in each direction.
- **Not covered at M0** (don't assume): ESN and NAT-T over a real exchange (only at contract level), rekey/lifetime expiry (the mock never emits `EXPIRE`), IPv6, transport mode, `ACQUIRE`, forwarder restart/resync.

### Findings from the M0 run that shape M1+
1. **`reqid` is 0 on every SA and SP** in a stock racoon2 config, so the forwarder must bind an SA to its policy by tunnel endpoints/selector (and SPI+dst on inbound), never by `reqid` alone.
2. **`natt_sport/dport` are populated (500) even when `natt_type` = none.** Ports are only meaningful with `natt_type != NONE` (now documented in `proto.h`).
3. **AEAD key blob = cipher key || 4-byte salt** (`enclen=20` for AES-128-GCM): confirmed against iked, matching what `librte_ipsec` wants.
4. **spmd always uses `spdupdate` (upsert) and calls `SP_DUMP` at startup**; SP_ADD must be idempotent and SP_DUMP must be cheap. ~16 UDP bypass SPs per stack (IKE ports) accompany 3 tunnel SPs (in/out/fwd) — the datapath must honor the IKE bypass or route IKE via the exception path.
5. **racoon's `RCT_*` enum numbers are unstable across versions** (upstream inserted `RCT_ALG_AES_GMAC` mid-enum while this work was underway). Translating by symbol to IANA IDs in the shim was the right call; unmapped algorithms (GMAC, DES, IPComp) are refused, not guessed.
6. **XFRM-native fields**: `mark`/`if_id` selectors are refused (`EOPNOTSUPP`) rather than silently widening a policy; `offload_*` hints are ignored. M4 inline crypto needs a protocol extension to carry `offload_ifname`.
7. **Upstream moves fast** (136 commits between my first clone and the final one). The patch is pinned to `2fd758a`; `./build.sh e2e` is the rebase check. Upstream `make install` (out-of-tree) currently fails late on a missing `01setkey` hook; unrelated to r2dp, worked around in `build-racoon2.sh`.

## M1 — Forwarder MVP (1 port, 1 worker)
- **Done (control plane)**: `fwd/` — `r2dp-fwd` daemon. `fwd/ctl.c` serves the
  r2dp control socket hardware-agnostically behind the `fwd/dp.h` vtable
  (HELLO/caps, GETSPI, SA_ADD/UPDATE/DEL/GET, SP_ADD/DEL/GET/DUMP, keys
  withheld; forwarder-allocated SPI; idempotent SP_ADD; cheap SP_DUMP).
  `fwd/main.c` + `fwd/dp.c` wire an optional DPDK dataplane
  (`-Denable_dpdk`); without DPDK it runs control-only.
- **Done (DPDK dataplane, SA layer)**: `fwd/dp_dpdk.c` — `rte_ipsec_sad`
  (SPI_DIP key, RW-concurrency) storing an opaque `rte_ipsec_sa` per installed
  SA; `crypto_openssl0` AES-GCM + `net_tap0` ingress vdevs; SA install/delete
  lowered from the r2dp control socket into the SAD. EAL args passthrough.
  **Verified on Fedora 24.11.4**: EAL + crypto + tap come up; a raw client
  drives HELLO→GETSPI→SA_ADD→SA_DEL all status 0 into the SAD, keys withheld.
- **Done (DPDK packet path, v1)**: run-to-completion worker on a slave lcore;
  `net_tap0` bring-up (configure/rx/tx/start/promisc); rx→classify→tx loop
  with per-second counters; IPv4 ESP (→crypto path, counted) + IPv4 UDP
  (→IKE exception path, counted). **Verified**: bridge `r2dp-tap`→veth→netns,
  ping through; worker shows `rx=73 tx=73 drop=0 ike=18` — traffic flows
  through the DPDK datapath, zero drops.
- **Done (ESP crypto path)**: full security stack per SA — OpenSSL cryptodev
  config/start + session + op mempools, `rte_cryptodev_sym_session_create`,
  `rte_ipsec_session` bound via `rte_ipsec_session_prepare` (CPU_CRYPTO,
  24.11 pattern), SAD value = the session. Worker splits ESP vs non-ESP; ESP →
  SAD lookup (SPI+DIP) → `pkt_crypto_prepare` → enqueue → dequeue →
  `pkt_process`. **Verified**: SA_ADD builds the AES-GCM session on
  crypto_openssl0 (status 0, no crypto errors); worker regression clean
  (zero drops).  *Remaining: the end-to-end "a real ESP packet decrypts"
  proof + the iked-over-veth interop exit gate (below).*
- **Builds (control plane + SAD + packet loop + crypto path)**: meson + tests
  4/4 (`test_proto`, `test_mock`, `shim_contract`, `smoke_fwd`); DPDK build
  links and runs.
- **Remaining (M1 exit gate)**: drive a real encrypted ESP flow through the
  forwarder (iked over a veth/VTAP against the patched racoon2 backend =
  kernel-XFRM↔forwarder ESP interop), proving traffic round-trips and the SAD
  is the source of truth. Candidate DEFER: rte_acl SPD → M3 (M1 = linear
  lookup in ctl.c).

### M1 data-plane status (2026-10-24)
- **Done (inbound structure)**: forwarder is now a two-tap bump-in-the-wire —
  outer tap (ESP side) + inner tap (plaintext side); worker polls both;
  inbound ESP → SAD lookup → AES-GCM decrypt → cleartext forwarded to the
  inner tap (previously dropped).  **Verified on Fedora 24.11.4**: two-tap
  mode brings up `r2dp-tap` + `r2dp-tap-inner` in PROMISC, worker runs
  `outer=0 inner=1`, control-plane SA install unaffected.  Commit `444d287`.
- **Remaining (data-plane crypto proof + outbound)**: the outbound encrypt
  leg (inner plaintext → ESP out outer) is not yet wired; a real encrypted
  ESP packet has not yet been shown to decrypt through the forwarder.
  CRITICAL FIX 2026-10-25 discovered during this work: the tunnel SA was
  NEVER actually installed in the dataplane (`prm.tun.next_proto` was set to
  ESP instead of IPIP → `rte_ipsec_sa_size()` = -22), and ctl.c swallowed the
  error (always replied status 0).  Fixed (`0185dad`): next_proto=IPIP +
  error propagation + SA table rollback.  The interop still reaches
  ESTABLISHED; the SA now genuinely lands in the SAD, so the data-plane
  crypto test has a real path to run on.
- **Deps**: DPDK >= 23.11 LTS (libdpdk), libnuma, python3-pyelftools (DPDK build), hugepages or `--no-huge`.
- **Exit gate (netns + net_tap/crypto_openssl vdevs)**: kernel XFRM <-> forwarder ESP interop both directions; iked negotiates via TAP and traffic flows; `r2dpctl dump` matches SAD.

## M2 — Lifecycle & protocol coverage
- **Builds**: lifetime tick + EXPIRE, hard-expiry RCU swap, ESN + replay window, AES-CBC + HMAC-SHA2, IPv6, NAT-T (UDP/4500 demux, non-ESP marker), HELLO capability bitmaps driving `rcpfk_supported_*`.
- **Deps**: none new (crypto_openssl / crypto_aesni_* vdevs).
- **Exit gate**: soft expiry triggers iked rekey with no packet loss in a ping flood; `samples/linux-matrix` rows (incl. NAT-T, ESN) pass against the forwarder; kernel-XFRM oracle matches on all algs.

## M3 — Multicore & update safety
- **Builds**: RSS multi-queue workers, per-lcore counters, rte_rcu_qsbr table swaps, SA-pinned ordering notes (one SA = one core), hugepage/NUMA setup docs.
- **Deps**: multi-queue-capable PMD (or net_tap multi-queue for CI), perf tools (optional).
- **Exit gate**: N-tunnel scale test linear to core count; table churn (SA/SP add/del at 1k/s) under traffic with zero drops/crashes (ASan/TSan builds clean).

## M4 — Offload, on-demand, MTU
- **Builds**: `rte_security` inline crypto path, ACQUIRE for on-demand SAs, fragmentation + PMTU/ICMP, resync-on-reconnect snapshot hardening.
- **Deps**: inline-crypto NIC (hardware; optional, gated behind caps).
- **Exit gate**: forwarder restart mid-session resyncs without iked restart; PMTU black-hole test passes; inline path matches CPU path byte-for-byte.

## Multi-backend strategy (r2dp forwarders)

r2dp is a **control-plane protocol** (`proto.h`: SAD/SPD CRUD over a unix
SOCK_SEQPACKET socket); it is not a datapath API. A "backend" is therefore a
*forwarder implementation* that owns a packet engine and speaks the same r2dp
southbound. racoon2, `libr2dp`, and the shim are shared and unchanged across
backends; the `HELLO`/`HELLO_ACK` `features` + `enc_caps[8]`/`integ_caps[8]`
bitmaps (queried via `rcpfk_supported_enc/auth` / `r2dp_cap`) already let
each engine advertise what it can do and let racoon2 refuse the rest. That
handshake is the multi-backend seam — never fork the wire protocol per
backend.

**Target backend sequence** (each is a separate forwarder behind the same
r2dp contract; earlier milestones are the baseline, not a fork):

1. **DPDK** — M1–M4 as scoped. Userspace poll-mode, `librte_ipsec`, no special
   hardware, CI-testable. The always-available software baseline.
2. **P4-DPDK** — P4 datapath compiled onto DPDK (`p4c`/PNA backend). Same
   protocol, software-testable in CI, but the *same* `.p4` can later target a
   switch ASIC (Tofino-class) or SmartNIC. Gives the write-once →
   silicon-upgrade path; P4's portability only pays once the P4 abstraction is
   kept, so it is **not** parallel work in M1.
3. **XDP2** — [xdp2-dev/xdp2](https://github.com/xdp2-dev/xdp2) (rc3) is a
   **programming model / compiler**, not a competing engine: define a parse
   graph once and it emits an XDP/eBPF program *and* a standalone
   userspace/DPDK app. That matches the "external forwarder that can also run
   in-kernel" story and avoids hand-maintaining two datapaths. Young (rc3,
   some BPF-stack test skips), so treat as a *spike*, not the near-term bet.

**Protocol invariants every backend must honor** (from the M0 run, above):
- Forwarder is the SAD source of truth: `GETSPI` allocates; `SA_ADD`/`SP_ADD`
  must be idempotent; `SP_DUMP` is called at spmd startup and must be cheap.
- Bind SA ↔ policy by tunnel endpoints/selector + (SPI+dst inbound); never by
  `reqid` alone (finding 1).
- AEAD key blob = cipher key ‖ 4-byte salt (`enclen=20` AES-128-GCM), matching
  `librte_ipsec` (finding 3).
- Datapath must honor the ~16 UDP IKE bypass SPs or route IKE via the
  exception path (finding 4).
- Unknown transforms / XFRM-native `mark`/`if_id` are refused (`EOPNOTSUPP`),
  not silently widened (findings 5, 6).

Keeping these in every backend is what prevents "multi-backend" from decaying
into per-backend protocol forks.


### M1 interop lab (2026-10-24) — control-plane KM↔forwarder proven
- **Built** racoon2 `--with-km-backend=r2dp --with-r2dp=PREFIX` (autoreconf +
  configure detects libr2dp via pkg-config `r2dp.pc`).
- **Fixed** `r2dp.pc` Cflags: must be `-I{includedir}`, not `-I{includedir}/r2dp`
  (headers are `include/r2dp/*.h`, included as `<r2dp/proto.h>`) — without this,
  the racoon2 r2dp build fails `fatal error: r2dp/proto.h: No such file`.
- **Interop proven (control plane)**: kernel-xfrm iked (netns A) <-> r2dp iked
  (netns B, both spmd+iked over libr2dp to this forwarder), IKEv2 over the TAP;
  both reach `ESTABLISHED`; iked B does GETSPI + SA_ADD (ESP/tunnel/AES-GCM,
  enckeylen=20) to the forwarder — the external forwarder is the SAD.  Requires
  all daemons `-F` (foreground: no pidfile, per matrix) + distinct
  `RACOON2_ADMIN_SOCK` + per-netns spmif (two-peers-on-one-host).
- **Known incomplete**: forwarder dataplane `esp=0` in this layout — the packet
  path exists and is unit-verified, but the netns/bridge topology routes ESP to
  the kernel rather than through the forwarder's tap; finishing the
  data-plane-through-forwarder leg is the remaining exit-gate item.

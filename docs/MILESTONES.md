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

## M1 — Forwarder MVP (1 port pair, 1 worker)  ✅ DONE (with the deviations below)
- **Built**: `fwd/fwd.c` (`r2dp-fwd`), the shared control-plane engine `libr2dp/cp.c` (the mock now runs on it with no hooks), `tools/r2dpctl`, and the tests below.
  - SAD in an `rte_hash`, SPD in `rte_acl` (most-specific selector wins), static routes in `rte_lpm`.
  - Run-to-completion on one lcore: IPv4 ESP tunnel mode, AES-GCM-16 (AES-128/256) through `rte_cryptodev` (`crypto_openssl`), sequence numbers and a 64-packet anti-replay window.
  - Exception path: an optional third port (`net_tap`) is given the black port's MAC and carries ARP, IKE (UDP 500/4500) and ICMP for the gateway itself to the kernel, and the kernel's replies back out the black port.
  - Control plane: all state arrives through the r2dp protocol; unsupported SAs/SPs (AH, transport, ESN, NAT-T, non-GCM-16) are refused with `EOPNOTSUPP` and never half-installed.
- **Deps added**: DPDK ≥ 23.11 (`libdpdk-dev`), libnuma; tests: scapy + python3-cryptography, iproute2, iputils-ping.
- **Exit gates — met** (`./build.sh e2e -m 1 --racoon2 <checkout>` runs all of them from a clean clone):
  1. `fwd_e2e.sh`: **independent-implementation interop**. scapy+cryptography plays the remote gateway; a real kernel host sits behind the forwarder. Every ESP pad length (payloads 0–9 B), up to 1400 B, TTL handling, exact anti-replay window edges (distance 63 accepted / 64 rejected), and hostile input (bit flips, tampered sequence/AAD, unknown SPI, inner packet outside the selector, cleartext on a protected flow, truncated ESP). Counters are asserted **exactly** — 20 round trips, and every other drop reason must be zero.
  2. `ike_fwd_e2e.sh`: **iked + spmd + r2dp-fwd on both sides**. IKEv2 crosses both exception paths, each forwarder receives its SAs/SPs over r2dp, and hosts behind each gateway ping each other (incl. 1200 B) through the tunnel — so the keys iked derived agree on both datapaths. 0 auth failures, 0 cleartext bypass.
  3. Regression: `test_proto`, `test_mock`, `shim_contract`, `r2dpctl-vs-mock`, and the M0 mock IKEv2 gate all still pass.
- **Deviations from the plan (deliberate; read these)**
  - **`rte_cryptodev` directly, not `librte_ipsec`.** The installed package ships headers only and the IV/AAD layout `librte_ipsec` expects in the op private area is not documented there. Owning the ESP framing keeps M2 (ESN, lifetimes, per-SA counters) simple. Revisit if inline-crypto (M4) wants `rte_security` sessions.
  - **SAD is `rte_hash`, not `rte_ipsec_sad`** (same reason; trivially swappable).
  - **Kernel XFRM was not the oracle.** The sandbox kernel has no ESP or GCM support, so interop was proven against scapy (an independent ESP implementation) instead. Cross-checking against `ip xfrm` on a normal Linux host is still worth doing and has not been done.
  - **`r2dpctl dump`** only covers SPs (`sp-dump`); the protocol has no SA-dump message yet, so "dump matches SAD" is verified through `SA_GET` in tests rather than a CLI command.
  - **Red side has no ARP**: static neighbours/routes only. Only the black side has an exception path.
  - **Crypto is synchronous** (software PMD, spin-until-done). Fine for M1; M3/M4 need a pipelined path for async/inline devices.
- **Behaviours worth knowing**
  - No matching policy ⇒ forwarded in the clear (kernel semantics). A *failed* policy update is never allowed to look like "no policy": ACL contexts are rebuilt aside and swapped only on success, and a rejected update leaves the previous policy untouched.
  - Non-IPv4 traffic on the red/black fast path is dropped (fails closed for IPv6 until M2).
  - Default idle behaviour sleeps 50 µs when both rx queues are empty (`--idle-us 0` for pure polling).
- **Not covered at M1 (don't assume)**: ESN, NAT-T, IPv6, AH, AES-CBC/HMAC, transport mode; SA lifetimes and `EXPIRE` (so SAs never rekey from the forwarder side); fragmentation/PMTU (oversize ⇒ dropped and counted); multi-core; hugepages and real NICs (everything ran on `--no-huge` with `net_af_packet`/`net_tap` vdevs on a 1-CPU sandbox, so **no performance numbers exist**); forwarder restart/resync; per-SA counters outside the SIGUSR1 stats dump.
- **Defects found by review/tests during M1** (all fixed, kept here so the next person knows where the sharp edges were): ACL rebuild failure failed *open*; a rejected SP *update* removed the policy from the datapath while the control plane kept it; a test harness bug (`pkill -f` matched its own shell) and an RFC 4303 violation in my own test (ESP seq 0) that the forwarder correctly refused.

## M1.5 — Kernel reference backend (`r2dp-kfwd`)  ✅ DONE, partially verifiable in the dev sandbox
Purpose: a second, independent dataplane behind the same protocol, so the DPDK forwarder and the racoon2 shim can be checked against what the Linux kernel does with the *same* r2dp requests. Idea taken from two prototype mock forwarders (netlink passthrough; io_uring control loop), rebuilt on the shared control-plane engine — the prototypes themselves did not fit this tree (see "what changed from the prototypes").
- **Built**: `kfwd/xfrm.c` (r2dp ⇄ NETLINK_XFRM translation as engine hooks), `kfwd/kfwd.c` (daemon, `--io poll|uring`, `--no-probe`), `tests/kfwd_test.sh`, a `BACKEND=kernel` mode in `tests/e2e/fwd_e2e.sh`, and `r2dp_cp_dispatch()` in the engine for event loops that do their own receive.
- **Behaviour**
  - Every SA/SP is installed in the kernel *before* the client is answered; the kernel's own errno is what the client sees (e.g. `ENOSYS` when the kernel lacks the algorithm), and a refused request is **not** committed to the engine's state.
  - SA: ESP/AH, tunnel/transport, AEAD (GCM/CCM/ChaCha20-Poly1305), AES-CBC/3DES/NULL + HMAC/XCBC/CMAC, NAT-T encapsulation, ESN with replay bitmap, lifetimes, IPv4 and IPv6 — via a transform table. NEWSA falls back to UPDSA on `EEXIST` (rekey). SPIs are allocated by the engine, not `XFRM_MSG_ALLOCSPI`, so a collision with a state created by someone else shows up as `EEXIST` at install time.
  - SP: `UPDPOLICY` (upsert), selector incl. protocol/ports, template with endpoints/reqid/mode, action allow/block; specificity is mapped onto kernel priority (more specific ⇒ lower number). Bundles are refused.
  - Startup probe: instead of trusting `/proc/crypto` (algorithms autoload on first use), it installs and removes a throwaway state per transform on TEST-NET addresses and advertises only what worked, so iked never proposes something the kernel will refuse. `--no-probe` advertises the whole table.
  - `--io uring` (**experimental**): the control socket is served with io_uring (accept/recv SQEs) instead of poll. **It does not and cannot speed up the datapath** — in this backend packets never leave the kernel. It only changes how control messages reach the engine, which matters little at control-plane rates. A genuinely io_uring-based *dataplane* would be a different program (a userspace forwarder doing packet I/O on TAP/AF_PACKET sockets), not this one.
- **Verified here (dev sandbox)**: `kfwd_test.sh`, under both control loops, reads the kernel's own tables back with `ip xfrm`: selectors, direction, block/allow, templates, reqid, upsert-in-place, delete, duplicate ⇒ `EEXIST` with kernel unchanged, priority ordering; plus 60 connect/serve/disconnect cycles, a garbage datagram and an oversized datagram (each drops only that client) and clean exit on SIGTERM.
- **NOT verified (read this)**: the sandbox kernel has **no ESP and no AES-GCM**, so no SA was ever actually installed. What *is* verified for SAs: the message is well-formed enough to get past the kernel's attribute validation up to the algorithm lookup, the kernel's refusal propagates to the client, nothing is half-committed, and the kernel's explanation is logged. Consequently **unverified**: the correctness of every SA attribute (AEAD key/ICV sizing, CBC+HMAC truncation, ESN bitmap, NAT-T), the CCM/ChaCha/3DES entries, IPv6, transport mode, the kernel dataplane itself, and `BACKEND=kernel fwd_e2e.sh` (it skips with exit 77 here; first run on a normal Linux host will probably need debugging). The same suite must be run on a real host before trusting kfwd as a conformance reference.
- **Known differences vs the DPDK forwarder (expected, worth testing deliberately)**: no matching policy ⇒ both forward in clear, but after decapsulation the DPDK forwarder *requires* the inner packet to match a PROTECT policy for that SA's tunnel and drops it otherwise, whereas the kernel only drops it if a policy applies and is violated; forwarded traffic needs an `fwd` policy in the kernel (the DPDK forwarder accepts `in` or `fwd`). kfwd leaves its kernel state behind when it exits.
- **Not done**: kernel → client events (`EXPIRE`, `ACQUIRE`) — the engine has no push path yet (an M2 prerequisite for both backends); cleanup of kernel state on exit; running the iked+spmd stack against kfwd.
- **What changed from the prototypes**: they called an `r2dp_cp_new(handler, ...)` API that does not exist; sent zero-filled XFRM messages with the field mapping left as a comment; never read the kernel's ACK and always replied success (so they could not fail a conformance check); the io_uring one used `SOCK_STREAM` with fixed 4096-byte reads/writes against a `SOCK_SEQPACKET` protocol, built replies without magic/version/length (our own client rejects them), leaked accept state, bypassed the engine (no SPI allocation or EEXIST/ENOENT semantics), and would not compile (`errno` unincluded; misuse of `io_uring_sqe_get_data` on a CQE).

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

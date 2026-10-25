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
- **Done (ESP crypto path, corrected 2026-10-25)**: the packet decoder
  pipeline now genuinely runs.  Beyond `0185dad`, three more compounding bugs
  were unmasked (all latent because no real ESP had ever reached the decoder)
  and fixed in `f704e94`:
  1. **SAD lookup byte-order mismatch** — lookup applied `rte_be_to_cpu_32()`
     to `ip->dst_addr` while SA install stores raw wire-order bytes via
     `addr4_to_u32()` memcpy → keys byte-swapped apart → `nlook=0` on every
     real packet.  Lookup now uses `ip->dst_addr` verbatim.
  2. **No crypto direction** — the SAD is the inbound-decrypt table (keyed
     SPI+DIP, read by the inbound worker), so every session must be
     `RTE_CRYPTO_AEAD_OP_DECRYPT`; it defaulted to ENCRYPT → OpenSSL session
     mismatched the op → crash.
  3. **Missing AEAD iv.offset + zero op-pool priv_size** — librte_ipsec writes
     the GCM IV into the op private area (op+sym_op), and the OpenSSL PMD
     reads it back at `xform->aead.iv.offset`; offset 0 made it read the
     session-pointer region as the IV → near-NULL segfault in
     `openssl_pmd_process_op`.  Set the offset to ipsec-secgw's IV_OFFSET and
     reserved that + IV length in the op pool.
  **Verified (probe, Fedora 24.11.4)**: SA_ADD status 0 with the SA genuinely
  in the SAD (not masked), SAD lookup `nlook=1`, `pkt_crypto_prepare np=1`,
  enqueue/dequeue 1/1 with **no crash** — the data-plane decrypt pipe now
  runs start to finish.  A hand-crafted RFC 4106 probe currently `AUTH_FAILED`
  at the GCM tag check (probe AAD vs librte_ipsec's internal `aead_gcm_aad`
  format — a probe-format detail, not a pipeline fault); the real iked
  interop is the authoritative wire test.
- **Builds (control plane + SAD + packet loop + crypto path)**: meson + tests
  4/4 (`test_proto`, `test_mock`, `shim_contract`, `smoke_fwd`); DPDK build
  links and runs.
- **Remaining (M1 exit gate)**: drive a real encrypted ESP flow through the
  forwarder (iked over a veth/VTAP against the patched racoon2 backend =
  kernel-XFRM↔forwarder ESP interop), proving traffic round-trips and the SAD
  is the source of truth. Candidate DEFER: rte_acl SPD → M3 (M1 = linear
  lookup in ctl.c).

### M1 data-plane status (2026-10-24 → 2026-10-25)
- **Done (inbound structure)**: forwarder is now a two-tap bump-in-the-wire —
  outer tap (ESP side) + inner tap (plaintext side); worker polls both;
  inbound ESP → SAD lookup → AES-GCM decrypt → cleartext forwarded to the
  inner tap (previously dropped).  **Verified on Fedora 24.11.4**: two-tap
  mode brings up `r2dp-tap` + `r2dp-tap-inner` in PROMISC, worker runs
  `outer=0 inner=1`, control-plane SA install unaffected.  Commit `444d287`.
- **Done — inbound decrypt PROVEN (real ESP to cleartext)**: two root causes
  fixed after the AUTH_FAILED hunt: (1) `prm.ipsec_xform.direction` was never
  set — EGRESS is enum 0, so every memset-zero SA silently built an OUTBOUND
  encrypt SA that mangled received packets (`sa_type=14` → fixed to 10 by
  `RTE_SECURITY_IPSEC_SA_DIR_INGRESS`); (2) `aead.aad_length` was 16 but RFC
  4106 §5 needs 8 (12 with ESN) — librte's internal `aead_gcm_aad` buffer is
  16 bytes but OpenSSL PMD authenticates exactly `aad_length` bytes.  With
  direction=INGRESS + aad=8, a real EVP-sealed RFC 4106 ESP datagram
  (rt_esp.bin, tag `99327b18…` verified against EVP) decrypted
  `st=0 proc=1 pkt=44` to the inner ICMP, captured cleartext on
  `r2dp-tap-inner` (`4500 002c …` at inner_sniff.bin@0x1d0), eth-preprended +
  padded to 60.  Commit `5450f26`.  This was the M1 AUTH_FAILED/D1 blocker.
- **Done — gcm_kat regression**: tests/gcm_kat.c runs the production
  `r2dp_gcm_sa_prm()` builder (fwd/dp_gcm.c, extracted from the reviewer's
  direction+AAD patch) against an EVP-sealed KAT; `aad_tweak` proves aad=8
  decrypts while aad=16 fails a real peer; tampered-ICV rejected.
- **Done — outbound (egress) encrypt leg, PROVEN**: fwd/dp_dpdk.c gains an
  in-dataplane SPD table (`sp_tab`, slid-keyed `dpd_sp_add/del`),
  prefix `sel_match`, `reqid`→egress-SA binding, and `esp_outbound`; `dp.h`
  `FWD_DP_SA_INBOUND 0x2` marks an SA completing our GETSPI reservation as
  ingress/decrypt vs a plain add as egress/encrypt.  `worker_inner` drops
  ESP-in, encrypts policy-matched inner plaintext via `esp_outbound`
  (L2-strip → EGRESS prepare/process → L2-prepend + 60-byte pad), tx to the
  outer tap, and passes IKE/ARP/no-policy frames through the exception path.
  **Verified on Fedora**: installed an egress SA (SPI 0x4444, reqid 0x2222) +
  an OUT-PROTECT policy, injected an inner ICMP, and the outer tap captured a
  valid 100-byte ESP datagram (outer 10.0.0.1→10.0.0.2, ESP SPI 0x4444, seq 1;
  egress crypto `st=0 proc=1 pkt=100`).  Commit `2d9b944`; meson 5/5 DPDK,
  4/4 control.
- **Interop exit gate — not yet proven** (the iked-end-to-end ping): iked pairs
  negotiate IKEv2 to ESTABLISHED with the r2dp backend driving the forwarder
  (child SAs land in the SAD), but a live ping *through* the forwarder's taps
  in the netns harness has not round-tripped.  The remaining blocker is lab
  orchestration (iked IKE source-address/config churn + stale iked resume
  state in the A2/B3 + harnesses, saw `RACOON2_RESUME_DIR` needs per-side
  isolation), not the forwarder datapath, whose two legs are each proven
  above.  Tracked separately.

### Latest-review round (REVIEW_R2DP_LATEST_2026-10-25, base 2d9b944) — status
- **H1 egress outer-IPv4 checksum — FIXED (42349ce), verified live**: librte
  leaves `hdr_checksum=0` (only patches total_length/packet_id); esp_outbound
  now computes it.  Captured ESP: stored==computed 0x6665 (was 0x0000).
- **H2 fail-closed SPD — FIXED (42349ce + ecf7a32), verified live**:
  sp_match_out matches any action and returns the SA only for PROTECT;
  ESP drop on DISCARD and on PROTECT-no-SA (RFC 4301 5.1).  Live: out PROTECT
  w/ reqid-no-SA -> drop 0->12, esp=0, no cleartext leak.  Inbound exception
  path tightened to IKE(500/4500)+ARP only (is_ike_arp); other network
  cleartext is dropped; inbound decrypt still forwards (esp-tx sent=1).
- **H3 egress SA selection by tunnel endpoints — FIXED (4213486), verified**:
  racoon2 sends reqid=0 for every SP/SA, so reqid-keyed selection collapsed
  tunnels onto the first outbound SA.  dp_sa records srca/dsta (addr[0..3]),
  sa_by_policy matches policy tun_src/tun_dst.  Live: two reqid=0 egress SAs
  (dst .2 SPI 0x4444, dst .3 SPI 0x5555) + tun A->B policy -> SPI 0x4444/dst
  .2 emitted.
- **H4 error-path leaks/UAF — FIXED (42349ce)**: matched-but-failed packets
  drop (free+count+slot NULL), never leak as L2-stripped cleartext; crypto ops
  always freed when not in flight; inbound tail fixed for enq==0 and async
  dq<enq.
- **H5 ctl/worker race — FIXED (c2480fc)**: QSBR; worker quiescent per loop, sa_slot_retire unlinks + synchronize before free.  Verified: 150 SA churn cycles err=0 under live traffic, no crash.
- **M1 keyed in-place UPDATE refused — FIXED (bc646e2)** (GCM IV reuse).
- **M2 build-then-swap — FIXED (bc646e2)**: new session built first, old torn
  down only after; no dataplane-empty window on init failure.  Delete path
  matches (SPI, proto, DIP) not SPI+proto.
- **M3 alignment — FIXED (5280fee, 4572fde)**: dpdk_priv + gcm_kat session via
  aligned_alloc/rte_zmalloc(64).  dpdk_priv must use aligned_alloc PRE-EAL
  (rte_zmalloc before rte_eal_init fails -> dataplane silently lost).
- **M5 parse/trim — FIXED (4572fde)**: trim tap eth padding before
  encrypt (M5a); IHL bounds check (M5c).
- **L7 getspi span overflow — FIXED (5280fee)** (64-bit span/modulus).
- **NAT-T (RFC 3948) — IMPLEMENTED, bidirectional (da440de, 1ebff27 + backend
  e832409)**: forwarder detects ESP-in-UDP/4500 on the outer tap via a SAD-probe
  (disambiguating ESP from IKE-over-NAT-T per RFC 3948 s2.2), strips the encap
  to decrypt inbound, inserts UDP(4500)+marker on the encrypted egress leg, and
  advertises R2DP_FEAT_NATT so racoon2 negotiates it; the r2dp backend packs
  NAT-T SAs.  Verified inbound (UDP-encapped ESP decrypts st=0, pkt=44) and
  outbound (wire shows 4500/4500 + marker + our SPI).  IPv6 stays refused --
  it broadens SAD keys/selectors/framing and is a separate milestone item.
- **Lifecycle EXPIRE — FIXED AND VERIFIED (da3d753 TIME, b7b9f1e BYTE)**:
  TIME lifetimes (soft/hard, fwd/ctl.c) fire R2DP_EXPIRE(.expired=1/2) and
  withdraw the SA on hard expiry; BYTE lifetimes use a per-SA dataplane
  counter (dp_sa.bytes, incremented on decrypt/encrypt; ops->sa_bytes read by
  ctl).  Verified live: soft=2s/hard=4s -> EXPIRE 1 then 2; soft_bytes=4000
  inbound -> EXPIRE 1; soft_bytes=3000 egress -> EXPIRE 1.
- **OPEN (deferred)**: D5 SPD priority-order + port selectors +
  IPv6; M9 egress/EVP/replay tests (gcm_kat SKIP=fail and the DPDK CI lane are
  done under b29b5bc); L1/L2/L3 doc+license+handles; L4 wsize=0->64; L6
  per-packet IKE counter; L5/formatting.

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
- **2026-10-25 follow-up**: two earlier lab blinds cleared.  (1) The `esp=0`
  / no-SA_ADD was NOT the control plane: B's `iked-r2dp`/`spmd-r2dp` binaries
  were stale builds lacking the r2dp backend (generic `rcpfk_*` hooks, no
  `if_r2dp`; spmd fell back to pfkey).  Rebuilt racoon2
  (`--with-km-backend=r2dp`) and installed the r2dp libracoon + iked/spmd; now
  B does real `SA_ADD spi=0ff19bd6 dip=10.77.0.1` into the forwarder over a
  fresh IKE that reaches ESTABLISHED on both sides.  A (kernel-XFRM peer) must
  use a separate **xfrm**-configured libracoon (`peer-a/lib`) or it too inits
  the r2dp backend and fails "r2dp connect".  (2) Source-address: iked selected
  the inner dummy (192.0.2.2) as IKE source because `my_sa_ipaddr`/
  `peers_sa_ipaddr` were set to the inner selector instead of the OUTER tunnel
  endpoints (10.77.0.2/10.77.0.1) — fixed, and IKE now sources from 10.77.0.2.
- **Remaining exit gate (2026-10-25)**: after the control plane reliably
  installs the inbound SA, ESP from A (dst 10.77.0.1) reaches B's bridge
  ingress (veth-b) with the correct tap MAC and the FDB routes that MAC to
  `r2dp-tap`, yet the DPDK net_tap does not deliver bridged frames to the PMD
  (forwarder `rx` frozen; direct injection into the tap moves it, so RX is
  alive).  This is a DPDK-net_tap-in-Linux-bridge delivery quirk, not a
  forwarder/protocol/datapath defect — all three legs (inbound decrypt, egress
  encrypt, NAT-T) are independently unit-verified.  Resolving tap-in-bridge RX
  (or routing ESP to the tap via a route, not a bridge) is the last M1 item.

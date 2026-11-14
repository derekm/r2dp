# P4 backend (r2dp) — design & first-behavior plan

Status: **in progress.** The full `.p4`/PNA compile path works (p4c-dpdk on
`.165`, compiled `p4/r2dp.out`) and the `fwd/dp_p4.c` backend loads **and runs**
the SWX pipeline: `--dp p4` brings up codegen->.so->build_from_lib, a cryptodev,
the ipsec extern, a packet-path worker (`rte_swx_pipeline_run` + `rte_swx_ipsec_run`),
and serves the r2dp control socket (SA/SP install + commit verified).  What is
NOT done: real packet I/O (nothing feeds the ring ports yet) and the first-spec
limits in §8.  Superseded pre-toolchain sections: §3/§5/§6/§7 (see §8).

## 1. Why this is buildable now

`r2dp` is a control-plane protocol (`include/r2dp/proto.h`: SAD/SPD CRUD over a
unix `SOCK_SEQPACKET` socket).  The dataplane is a "backend" — a forwarder that
owns a packet engine and speaks the same southbound.  Everything except the
packet engine is **backend-agnostic and already exercised end-to-end by the
DPDK backend**:

- `fwd/ctl.c` + `fwd/ctl.h` — the hardware-agnostic control server.
- `include/r2dp/proto.h`, `include/r2dp/client.h`, `libr2dp/` — wire contract +
  transport, shared by every backend.
- `fwd/dp.h` — the `fwd_dp_ops` vtable a backend implements (already comments
  "a P4/XDP2 backend would implement the same interface").
- `tools/mockfwd.c`, `tools/r2dpctl.c`, `tools/ctl_probe.c` — protocol peers.
- `tests/` — the complete unit + interop + e2e harness, independent of engine.

So *"we have enough of the DPDK backend"* is exact: the P4 leg is **one new
`fwd_dp` implementation** (`fwd/dp_p4.c`) behind the identical socket, reusing
ctl/proto/libr2dp/tests untouched.

## 2. The packet engine: P4-DPDK on the installed DPDK soft-switch

The P4-DPDK target compiles a P4 program (arch **PNA**) with the standalone
`p4c-dpdk --arch pna` (NOT `p4c --target dpdk`, which the driver rejects) into
a `rte_swx_pipeline` **text spec** (`.spec`), which a host program loads via
`rte_swx_pipeline_*` / `rte_swx_ctl_*`.

Confirmed present in the DPDK 24.11 build used on `.165` (and 25.11 on `.179`;
`/home/yescorp/dpdk-mb-prefix`, `librte_pipeline.so`):

- `rte_swx_pipeline` — load/run the spec pipeline.
- `rte_swx_ctl_*` — add/commit table entries (SAD, SPD), regarray, metarray,
  learner tables, stats.
- `rte_swx_ipsec` — the ESP/SPD **extern**: `rte_swx_ipsec_create/sa_add/
  sa_delete/run`, per-SA cipher/auth/aead + encap params, input metadata is a
  `sa_id` carried in the packet's metadata header.  This is the whole
  encrypt/decrypt + replay path, so the P4 program does parse + classification
  and defers crypto to this block — matching how the DPDK backend delegates to
  lookaside `crypto_*` or inline `rte_ipsec`.

Therefore the pipeline can be authored **either** from a real `.p4`/PNA source
(the write-once → ASIC path) **or** as a hand-written `.spec` (fast, zero
toolchain).  Both load into the same engine.

## 3. Toolchain reality (full `.p4` path) — SUPERSEDED by the working build

*This section was written pre-toolchain and is now stale; see §8 history.*

NOTE (post-implementation): `p4c`/p4c-dpdk **is** now built and working (see the
`p4-dpdk-swx` skill).  Facts that supersede §2/§3/§5:

- Compile = `p4c-dpdk --arch pna r2dp.p4 -o r2dp.out` — the **standalone**
  `build/backends/dpdk/p4c-dpdk` binary, NOT `p4c --target dpdk` (the driver
  only registers `dpdk-psa`).
- p4c-dpdk emits a **single** `.out` file (the SWX `.spec`) — no separate
  `.code` artifact.  `p4/r2dp.out` is that spec, checked in.
- The SWX runtime is bundled in DPDK 24.11+ `librte_pipeline.so` (no separate
  `librte_swx_pipeline.so`); Fedora's `dpdk` pkg ships it.

## 4. Mapping the `fwd_dp_ops` vtable to the P4/SWX engine

| `fwd_dp_ops` member | P4/SWX backing |
|---|---|
| `caps()` | Set `enc_caps`/`integ_caps` from the pipeline's advertised transforms (ipsec block caps; DPDK baseline ok initially). |
| `sa_add(add, sa, blob, blen)` | Inbound (`FWD_DP_SA_INBOUND`): `rte_swx_ipsec_sa_add` (AEAD key‖salt) + `inbound_table_0` entry keyed `(dst,spi)` → `ipsec_enable(sa_id)`. Outbound/egress SA: `rte_swx_ipsec_sa_add` with encrypt, NO SAD entry (reached through the SPD's `ipsec_protect(sa_id)`). `add==0`: `rte_swx_ipsec_sa_delete` + (if inbound) `inbound_table_0` delete, direction from the stored `e->dir`. |
| `sp_add(sp)` / `sp_del(sp)` | SPD table (`rte_swx_ctl_*` entry, exact `(src,dst,proto)`): action `ipsec_protect(crypto_sa_id)` / `spd_bypass` / `spd_discard`; `ipsec_protect` resolves the egress SA by tunnel endpoint + highest install gen (like `dpdk_spd.c` `sa_by_policy`), never the policy `slid`. **Accepts unbound OUT PROTECT and programs it to `spd_discard` (fail-closed), upgrades on `SA_ADD`/`SA_DEL`/rekey.** |
| `sa_bytes(spi,dip)` | **Not implemented**: returns `-1` (no SWX per-SA byte-counter surfaced yet). |
| `sa_set_hard_bytes/hard_time` | Hard-lifetime enforcement is intentionally **control-side (ctl.c)** and engine-agnostic; P4 backend returns 0 / tracks trivially or reuses the same ctl `check_lifetimes` logic. |
| `start`/`stop` | Launch packet threads running `rte_swx_pipeline_run`; load `.spec`/`.code` at start; stop join. |
| `idle()` | Compact/reconcile the SPD tables; drain deferred control work. |

Wire-format / protocol invariants in `MILESTONES.md` ("Multi-backend strategy":
SAD source of truth, SA↔policy bound by endpoints+selector not `reqid` alone,
AEAD blob = cipher‖salt with per-transform salt length incl. 3-byte CCM, IKE
bypass SPs or exception path, refuse-not-widen) all bind equally here and are
**already enforced by `ctl.c` before the vtable is called** — the P4 backend
inherits them for free.

## 5. File layout

```
fwd/dp_p4.c            # fwd_dp_ops implementation (vtable, start/stop, ctl glue)
                       #   fwd_dp_p4_probe() is declared in fwd/dp.h (built
                       #   only with -Denable_p4; dp.c provides a -2 stub)
p4/                    # P4 source + pipeline spec
  r2dp.p4              # PNA program: parse, headers, SPD/SAD tables, ipsec extern
  r2dp.out             # compiled SWX spec: p4c-dpdk --arch pna r2dp.p4 -o r2dp.out
  PLAN.md              # this file (+ §8 history of the post-implementation state)
fwd/main.c             # --dp p4 dispatches to fwd_dp_p4_probe
meson.build            # -Denable_p4 gates fwd/dp_p4.c into r2dp-fwd
COVERAGE.md, MILESTONES.md  # claim + plan updated when a runtime lane exists
```

## 6. Milestones

> NOTE: written pre-implementation. m0's "engine load + ctl" is DONE (load-and-run
> + SA/SP install committed); the "authored `.spec`" / hand-written path it
> presumes never happened — the full `.p4`/p4c-dpdk path was used instead.  What
> remains maps onto m1→m3 below, driven by real packet I/O, not a pass-through.

1. **p4-backend-m0 — engine load + ctl.** This milestone is met: `--dp p4`
   brings up the SWX pipeline (from `p4c-dpdk` output, not an authored spec),
   serves the r2dp socket, and a packet worker runs the pipeline.  SA/SP
   install verified by probe + `r2dpctl dump` (see §8 for the SPD-binding
   contract and how the bind is proven).
2. **p4-backend-m1 — first behavior (DPDK ingress ESP).** Inbound: parse
   eth/IP/ESP, SAD table `(dst,spi)` → ipsec block decrypt, inner forwarded.
   `dp_path`-style round trip + the negative cases (replay, unknown SPI,
   tamper) via the test harness.  Needs packet I/O into the rings.
3. **p4-backend-m2 — egress SPD.** OUT PROTECT/BYPASS/DISCARD via the SPD
   table; egress SA encrypt; `fwd_e2e` interop against an independent ESP peer.
4. **p4-backend-m3 — parity.** Exact drop-counter assertions, lifetimes,
   NAT-T keepalive/IKE exception, multi-worker (SWX is single-pipeline; workers
   = NIC queues feeding the pipeline), kernel-XFRM oracle cross-check; then
   `p4c`/PNA full path replaces the hand-authored `.spec` and the same `.p4` is
   the only source toward an ASIC.

Definition of done for the plan: m0 landable behind `--dp p4` with the control
lane green, m1–m3 each closing a named `COVERAGE.md` row.

## 7. Open questions the implementation must resolve

- SWX `ipsec` block's SAD key width / `sa_id` allocation scheme (currently a
  `uint32_t`; map our `(spi,dip)` → a compact sa_id the P4 metadata carries).
- Whether `p4c` DPDK/PNA emits `.spec`+`.code` that the installed 25.11 SWX
  version accepts, or whether the hand-authored `.spec` is the loadable input
  and `.p4` is forward-looking only.
- ~~IKE/ARP exception handling in a parse-defined pipeline (exception port vs a
  `bypass` table).~~ **Resolved `b60d0cd`** — non-ESP forwards clear (IPv4 routes
  by dst, ARP via `next_hop_preserve`), the pre-§8 drop is gone.
- SWX replay-window semantics vs our RFC 4303 window (the SWX ipsec block must
  be validated against the `dp_sa`/`kfwd` reference, exactly as the DPDK
  backend was).

## 8. History (post-implementation record)

**§8 update (2026-11-07, `b60d0cd`):** limits 1 and 2 (of the four below) closed
on-box; limits 3 and 4 were still open **at that commit** — 3 was proven closed
later at the extern (`8f0f38a`), 4 remains open.
- **Limit 1 (IKE/ARP dropped) — FIXED.** Non-ESP inbound/outbound frames
  (IKE UDP/500, ARP, plaintext) now forward clear instead of dropping:
  ARP is parsed (`arp_t`, ethertype 0x0806), forwarded with its L2 preserved
  via a `next_hop_preserve(port_id)` action that keeps the original ethertype
  (inbound forced to the inner leg id 2, outbound to the outer leg id 3);
  IPv4 clears route by dst LPM.  Inbound SAD still hits and ESP decrypt
  is intact (`crypto enq=32 deq=32` with the round-trip proof frame).
- **Limit 2 (every UDP/4500 parsed as ESP) — FIXED, zero-marker path proven.**
  RFC 3948 demux in the parser: `nat_demux` does `pkt.lookahead<bit<32>>()`
  on the candidate SPI; a zero marker (NAT-T keepalive / IKE behind NAT)
  terminates to `accept` and the frame is forwarded clear; a non-zero SPI is
  ESP-in-UDP.  On-box: UDP/4500 with `00 00 00 00` marker egresses inner
  clear (381 frames), never dropped, never offered to the SAD.
- **Limits 3 & 4 (as of `b60d0cd`):** crypto-failure->drop appeared still dead
  (`MainControlT_status` unwritten) and SPD was still exact
  `(src,dst,proto)` (no prefix/ANY/ports).  Limit 3's drop was later proven at
  the extern (`8f0f38a`); see the next update.  Only Limit 4 remains open.

**§8 update (2026-11-07):** Limit 3's *security* property is verified at the
crypto layer even though the P4 `status` branch is unwritten.
- **Limit 3 (crypto-failure-drop) — AEAD auth drop proven, at the extern.**
  `rte_swx_ipsec_post_crypto` calls `rte_ipsec_pkt_process`; on AEAD auth
  failure (`esp_inb.c` returns `-EBADMSG`) the failing mbuf is freed and
  never written to the pipeline's output ring, so a bad-ICV frame cannot
  egress the inner leg.  On-box: 2s of tampered-ciphertext ESP (8 ESP
  ciphertext bytes flipped, same SPI/seq) leaked **0** plaintext frames to
  inner while an intact frame decoded (398).  The P4 `status ==
  IPSEC_SUCCESS` branches are therefore dead-but-harmless: the drop already
  happened in the extern.  Do not "fix" the P4 status until/unless a real
  failure path that returns bad frames exists.
- **Limit 4 (SPD prefix/ANY) — DONE on the P4/SWX path (proven on `.165`).**
  `outbound_table` is now a WILDCARD (ternary) table on (protocol, src, dst);
  the runtime (`p4_spd_bind`/`p4_sp_del`) programs key + key_mask +
  key_priority at runtime.  How it works: p4c-dpdk lowers `ternary` to the SWX
  `wildcard` (ACL) match type; `rte_swx_table_wildcard_match_ops` has .add/.del
  NULL only because it has no *incremental* update — SWX updates such tables
  NON-INCREMENTALLY with a full rebuild on commit (`rte_swx_ctl.c`
  `table_rollfwd0` duplicates entries+pending_add+pending_modify1 and calls
  `table->ops.create`; DPDK "support non-incremental table updates", 21.05+,
  in v24.11).  This is the same `!ops.add` rebuild path the tree already
  used for `routing_table_0`'s `10/8` LPM entry (`fwd/dp_p4.c`), which was
  proven earlier — the SPD wildcard table is the identical mechanism on
  three fields.  `p4-dpdk-target`'s pipe_mgr drives the same path for
  P4Runtime ternary/TCAM entry add.  ACL key layout (the hard part, proven
  on-box): the ACL does NOT pack the key contiguously — `table_params_get`
  builds `key_mask0` from real IPv4 header bit offsets, so the key image is
  `[protocol@0][src@3][dst@7]` in NETWORK order (the 2 bytes 1-2 are the
  checksum gap), key_size=11, NOT a packed 9; masks are MSB-first
  (`/32`=ff ff ff ff, `/24`=ff ff ff 00, proto-ANY = mask[0]=0x00);
  `rte_acl` picks the HIGHEST priority match, so `p4_spd_prio` returns
  LOWEST for the most specific rule (0 for /32,/32 concrete-proto, growing as
  the selector broadens).  Full-rebuild update cost is O(table), a perf note
  not a wall.  Proof (all on `.165`, tap path): an exact-equiv /32,/32 udp
  PROTECT drives `ob_hit` + `crypto enq=32 deq=32` + ESP egress; a /32,/32 udp
  PROTECT alongside a /24 ANY BYPASS gives `ob_hit=120 ob_miss=0`,
  `a6=60` (specific PROTECT) and `a7=60` (broad ANY BYPASS) — the specific
  rule wins for its packets, the prefix/ANY rule matches everything else
  (including non-udp) without offering it to the SAD.  A real hardware TCAM
  target expresses the identical SPD as runtime rules with priority; the P4
  semantics map, the SWX byte-order/gap layout is the software-only sharp
  edge, now documented in `fwd/dp_p4.c`; see list below.

The plan above was filed before the P4 toolchain existed.  What actually
happened, per the review of commits `5b42982`..`6efe910` (`p4-dpdk-swx` skill
and the delegated `deleg_8f37ef0b` review):

- **Compile path verified working**: `p4c-dpdk --arch pna r2dp.p4 -o r2dp.out`
  (`6efe910`).  `p4/r2dp.out` is a genuine SWX spec.
- **Honest limits of this first spec** (at the original `6efe910` state; the
  ones now closed are marked — see the dated §8 updates at the top of this
  section before treating any as current):
  1. **Inbound `IKE` and `ARP` are dropped** — FIXED `b60d0cd`: non-ESP
     inbound/outbound (IKE UDP/500, ARP, plaintext) now forwards clear
     (IPv4 routes by dst, ARP forced inner/outer). Do not re-add the drops.
  2. **Every `UDP/4500` is parsed as ESP** — FIXED `91607d6`: RFC 3948
     zero-marker demux (keepalive/IKE clear, non-zero SPI is ESP-in-UDP).
     Do not re-add the blanket parse.
  3. The crypto-failure -> drop branch is **dead** in the artifact: nothing
     writes `MainControlT_status`.  RESOLVED `8f0f38a` at the extern —
     `rte_ipsec_pkt_process` frees a bad-ICV frame before it re-enters the
     pipeline, so the drop already happens; the P4 status branch is
     dead-but-harmless.  Do not "fix" the P4 status until a path that
     returns bad frames exists.
  4. **SPD is exact `(src,dst,proto)` only** — no prefix/ports/proto-ANY.  FIXED
     `a8aedd2`: now a WILDCARD (ternary) table with prefix/ANY selectors and
     per-rule priority (see §8 Limit 4 above).  Outbound miss -> `spd_bypass`;
     inbound miss -> `drop` is NOT `DR_NO_SA_IN`.
- **Runtime `fwd/dp_p4.c`** (`88ec62d`, `497952c`, `77551a8` … SPD-bind fix in
  the round-4 follow-up) implements `fwd_dp_ops` and now **loads and runs the
  SWX pipeline** end-to-end: `r2dp-fwd --dp p4` brings up
  codegen->.so->build_from_lib, a configured cryptodev, and the ipsec extern;
  `r2dp-ctl-probe` / `r2dpctl dump` show the SA and SP.  Verified live on
  `.165` (Fedora 44, DPDK 24.11, `--vdev crypto_openssl0`).  Runtime gotchas
  fixed: (a) iospec ring ports + ipsec rings must exist before build_from_lib
  (else ENODEV); (b) ipsec_create needs a real cryptodev (else EINVAL);
  (c) r2dp's AEAD blob is key||salt (extern strips trailing 4); (d) table
  action_ids are global per-pipeline — resolve with
  rte_swx_ctl_table_action_info_get, never hardcode.  Framed packet forward
  is proven (round-6): the worker RXes each ethdev leg into its input ring
  and TXes the output ring, and a real IPv4/UDP frame crosses
  inner→pipeline→outer over **root net_tap** (net_memif vdevs do not
  materialize on `.165` — see below; net_tap needs root, else TUNSETIFF
  EPERM and control-only fallback).  A full framed ESP forward
  (crypto + routing through the PNA tables) was later proven end-to-end
  (`f50470f` round-trip; `3e1f8bb` decrypt/HBO/routing) on root net_tap.
  All §8 limits 1-4 are now closed (Limit 4 SPD prefix/ANY proven 2026-11-07) —
  see the dated §8 updates at the top of this section.
- **SPD binding contract (rounds 4+5):** the control plane may install an
  OUT PROTECT policy with no egress SA yet (spmd loads SPD at startup, then
  GETSPI/SA_ADD) — so `p4_sp_add` **accepts** and never refuses.  It keeps a
  policy mirror (`pr->spd[]`) and programs an unbound OUT PROTECT to
  **`spd_discard` (FAIL CLOSED)**, never bypass (DPDK drops a matched OUT
  PROTECT with no SA, `DR_NO_SA_OUT`).  `p4_sa_add` (outbound add/delete) and
  rekey call `p4_spd_rebind` to (re)target `outbound_table_0`.  The egress SA
  is chosen by tunnel endpoint and **highest install generation**
  (`p4_sa.gen`), not slot index.  `table_entry_add` rejects a duplicate key so
  a re-bind/rekey is add-with-EEXIST-fallback-to-delete-then-add (never
  delete-first: a delete+failed-add would commit the deletion to the default).
  `p4_spd_rebind` propagates bind failure instead of swallowing it.  Bind and
  fail-closed are proven by `tools/p4_bind_probe.c` (meson
  `r2dp-p4-bind-probe`), which reads the forwarder log: SA-first → direct bind
  with NO discard; SP-first → `OUT PROTECT unbound -> DISCARD` then a rebind to
  `ipsec_protect` — not inferred from `r2dpctl dump`.
  **Honest scope of the fail-closed claim:** it holds for any SPD table hit
  (exact or prefix/ANY, see §8 limit 4 — SPD is now WILDCARD/ternary, proven
  2026-11-07).  A `R2DP_PROTO_ANY`/`/24` policy as spmd and the bind probe
  install now collapses to ONE wildcard entry (masked src/dst, proto byte
  masked off) and matches by prefix + priority.  DPDK honors ANY/prefix
  (`dpdk_spd.c:250,307`); this backend now does too.  The fail-closed
  unbound-PROTECT -> spd_discard still applies on a hit; a packet that matches
  NO rule falls to the `spd_bypass` default (mirroring DPDK's miss behavior).
  PLAN is explicit about this rather than overclaiming.
- **Framed forward proven (round-6):** a real IPv4/UDP frame injected on the
  inner tap (`r2pi`, outbound leg) is processed by the SWX pipeline and
  egresses the outer tap (`r2po`) — captured by tcpdump (`10.0.0.1.1024 >
  10.0.0.2.discard: UDP`, payload intact).  Worker counters (`out_rx in_rx
  out0 out1` + ring-occupancy, printed ~1s from the worker) show
  `in_rx=125 out0=96`, rings drained.  This proves I/O-ring bridge →
  pipeline run → next-hop → output-ring → eth bridge moves bytes end to end.
  The outbound default (`spd_bypass`) forwards it clear, as designed.
- **Framed ESP encrypt proven (round-8):** with an outbound SA
  (`aes-gcm-16`) + an exact OUT PROTECT policy bound, a clear IPv4/UDP
  frame injected on the inner tap is encrypted and egresses the outer tap
  as genuine tunnel-mode ESP — tcpdump shows outer IPv4
  `192.0.2.1→203.0.113.1`, proto 0x32 (ESP), `spi=0x01200000`,
  incrementing seq, distinct ciphertext per frame (fresh IV), plaintext
  gone from the wire.  Worker shows `ob_hit=N` with the per-action counter
  on ipsec_protect (`a6`), `crypto: enq=deq=N`, `out0` drained.  Root
  causes fixed: the default iospec was a stale 4-port file (no `port
  in/out 2` for the extern rings) so `tx port 2` was a no-op and no frame
  reached the extern — now always regenerated; and the extern's
  `.bsz` was all-zero so `rte_swx_ipsec_run` drained 0 frames — now
  `32 32 32 32`.  The extern's mbuf pool needs `priv >= 128`
  (`sizeof(struct ipsec_mbuf)`) or crypto prepare fails.
  **Round-trip proven (3e1f8bb):** the inbound/decrypt leg now works too.
  Inject the ESP a peer emitted on the outer leg (with a matching inbound SA
  installed) and the inner leg receives the restored plaintext -- inbound
  SAD hits (`hit=N`, ipsec_enable action), `crypto: enq=deq`, and the
  decrypted `10.0.0.1→10.0.0.2` proto-17 frame (original payload) exits the
  inner leg.  The decrypt-leg byte-order fixes (metadata tables match HOST
  order, not network; only header-field action data stays NBO) and inner-
  subnet routing are documented in §8 above.  So both directions of framed
  ESP crypto are proven; Limit 4 (SPD prefix/ANY) completed 2026-11-07 —
  see §8.  ctr() in
  bench/e2e_bench.sh still parses the DPDK `stats` format the P4 worker
  does not emit — the worker's own `pkt:` line is the P4-leg counter
  equivalent.

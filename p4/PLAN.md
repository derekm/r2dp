# P4 backend (r2dp) — design & first-behavior plan

Status: **in progress.** The full `.p4`/PNA compile path now works (p4c-dpdk on
`.165`, compiled `p4/r2dp.out`); the runtime `fwd/dp_p4.c` backend is built and
links against DPDK 24.11 SWX.  Remaining: get `r2dp-fwd --dp p4` to actually
load the pipeline and pass ctl/mockfwd.  This doc's §3/§5 were written before
the toolchain existed and are superseded (see the "history" note below).

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

The P4-DPDK target compiles a P4 program (arch **PNA**) with `p4c --target
dpdk --arch pna` into a `rte_swx_pipeline` **text spec** (`.spec`) plus a
`.code` blob, which a host program loads via `rte_swx_pipeline_*` / `rte_swx_ctl_*`.

Confirmed present in the DPDK 25.11 build already installed on `.179`

(`/home/yescorp/dpdk-mb-prefix`, `librte_pipeline.so`):

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
| `sa_add(add, sa, blob, blen)` | Inbound: `rte_swx_ipsec_sa_add` (AEAD key+salt, encap from tunnel endpoints). Outbound/egress SA: SAD table entry keyed `(spi,dip)` → action `set_ipsec_in(sa_id,e)`. `add==0`: `rte_swx_ipsec_sa_delete` + SAD del. |
| `sp_add(sp)` / `sp_del(sp)` | SPD table (`rte_swx_ctl_*` entry): match sel_src/sel_dst/pref/proto/ports → action `SPD_PROTECT(policy,e)` / `SPD_BYPASS` / `SPD_DISCARD`. Returns assigned `slid`. |
| `sa_bytes(spi,dip)` | SWX per-SA byte counter (ipsec block / table action counter); `-1` if unknown. |
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

1. **p4-backend-m0 — engine load + ctl.** `--dp p4` brings up the SWX pipeline
   (authored `.spec`), serves the r2dp socket, `ctl_probe` + `r2dpctl dump`
   pass, `fwd_e2e` control lane runs.  No packet path yet (or a pass-through
   parse).
2. **p4-backend-m1 — first behavior (DPDKingest ESP).** Inbound: parse
   eth/IP/ESP, SAD table `(spi,dip)` → ipsec block decrypt, inner forwarded.
   `dp_path`-style round trip + the negative cases (replay, unknown SPI,
   tamper) via the test harness.
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
- IKE/ARP exception handling in a parse-defined pipeline (exception port vs a
  `bypass` table).
- SWX replay-window semantics vs our RFC 4303 window (the SWX ipsec block must
  be validated against the `dp_sa`/`kfwd` reference, exactly as the DPDK
  backend was).

## 8. History (post-implementation record)

The plan above was filed before the P4 toolchain existed.  What actually
happened, per the review of commits `5b42982`..`6efe910` (`p4-dpdk-swx` skill
and the delegated `deleg_8f37ef0b` review):

- **Compile path verified working**: `p4c-dpdk --arch pna r2dp.p4 -o r2dp.out`
  (`6efe910`).  `p4/r2dp.out` is a genuine SWX spec.
- **Honest limits of this first spec** (fixes deferred, not bugs in the wiring
  yet):
  1. Inbound **IKE and ARP are dropped** (the apply block requires both
     `ipv4` and `esp` valid, else `drop_packet()`) — one-way vs the DPDK
     backend's IKE/ARP forwarding. An iked e2e will expose it.
  2. Every **UDP/4500 is parsed as ESP** — no NAT-T marker/keepalive demux.
  3. The crypto-failure -> drop branch is **dead** in the artifact: nothing
     writes `MainControlT_status`, so post-decrypt/encrypt always take the
     success path. Do not wire a test expecting bad-ICV drops here yet.
  4. **SPD is exact `(src,dst,proto)` only** — no prefix/ports/proto-ANY, so an
     r2dp OUT policy / IKE bypass SP does not collapse to one entry.  Outbound
     miss -> `spd_bypass` matches DPDK; inbound miss -> `drop` is NOT
     `DR_NO_SA_IN`.
- **Runtime `fwd/dp_p4.c`** (`88ec62d`, `497952c`) implements `fwd_dp_ops` and
  builds/links against DPDK 24.11 SWX.  Open: `rte_swx_pipeline_build_from_lib`
  returns `ENODEV` (the `ipsec_accelerator` extern object isn't instantiated by
  the codegen `.so` — empty `extobjs[]`); the pipeline is not yet load-and-run,
  and `direction[]`/`ipsec_port_*` regarrays would need programming before the
  first packet.

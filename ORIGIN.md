# Provenance

Landed from Mark Wilcox's `r2dp-claude.zip` (Telegram, 2026-10-24).

The zip had **no git history** (no `.git`, no commits to preserve).

**Shipped in the zip:** `include/r2dp/proto.h`, `tools/mockfwd.c`,
`patches/racoon2-r2dp-backend.patch`, `build.sh`, `ike_e2e.sh`, `README.md`,
`MILESTONES.md`.

**Claimed by his README but ABSENT from the zip** (empty dirs only):
- `include/r2dp/client.h`
- `libr2dp/`
- `tests/`

Those were **reconstructed** in this repo from the `proto.h` wire contract
and the `client.h` call-sites in `shim/if_r2dp.c` + `tools/mockfwd.c`:

- `client.h` — the full client/server API surface.
- `libr2dp/libr2dp.c` — transport (SOCK_SEQPACKET framing), validation,
  capability query, message accessors, address <-> sockaddr helpers.
- `meson.build` (library + mockfwd + tests) and the M0 tests
  `test_proto`, `test_mock`, `shim_contract`.
- GitHub Actions CI (gcc + clang, plus ASan/UBSan).

The racoon2 backend in this repo is the original `patches/...`; the live
`lib/if_r2dp.c` in racoon2 `derekm/racoon2` PR #2 is the same code, and that
PR links here for the buildable library.

# Contributing to R2DP

R2DP is a contributor-driven project. This file sets out, plainly, how
contributions work and who owns what. It is **expectation-setting, not legal
advice** — for enforceable terms we rely on the repo's license plus any CLA
we adopt; read this as the social contract, and ask before assuming more.

## What we're building

R2DP lets racoon2's IKE daemon (`iked`) and policy daemon (`spmd`) drive an
external forwarder (e.g. a DPDK IPsec app) instead of the kernel, over a
PF_KEY-shaped protocol on a unix socket. The current milestone map:

- **M1** — DPDK forwarder dataplane (the live focus)
- **M2** — lifecycle & protocol coverage (NAT-T, ESN, time/byte EXPIRE, IPv6)
- **M3** — multicore & update safety
- **M4** — offload, on-demand SAs, MTU/PMTU

The `lineage` branch holds the whole commit DAG; every commit there is built
and tested independently by `tests/ci_dag.sh`. The `usage` and `agent`
branches hold spend/ledger and agent-memory context respectively.

## This is a recruitment drive

We are actively recruiting contributors to build R2DP out — contributors, not
employees. There is no nationality, employer, or credential gate. If you can
move a milestone item forward (DPDK, core C, crypto, networking, testing,
docs), you're welcome. Remote and asynchronous collaboration is expected.

## Ownership: contributors own what they contribute

This is the core rule:

> **Each contributor retains ownership (copyright) of their own
> contributions.** Nothing in this project transfers a contributor's IP to
> the project or to any other contributor.

Contributions are your source code, your documents, your tests — and, where
you contribute them, your user-messages/prompts. You keep your rights in all
of it.

## License grant: contributing a prompt licenses its use

Open-source contribution is not "giveaway — it is a *license*. By
contributing to R2DP you grant the project the right to use that
contribution, **including by using it as a prompt/input to generate
derivative actions and outputs** (agent turns, derived code, tests, docs,
further analysis). Specifically:

- The grant is **non-exclusive and revocable only per the repo license** —
  you keep ownership, we get the right to build on it.
- It applies to **what you actually contribute in readable form**. Message
  bodies committed to the repo are **encrypted by default** (see
  `usage/`); ciphertext nobody can read is not a contribution of prose.
  The grant takes effect when a contributor **knowingly discloses** a
  readable message/prompt (e.g. by committing plaintext or by approving its
  disclosure with the ledger key).
- Derived works are licensed back to contributors on the same terms —
  nobody locks the derivative behind a wall the original contributor can't
  use.

## How to contribute

1. **Claim a milestone item** — open an issue or comment on an existing one
   before starting, so we don't clobber each other.
2. **Branch from the relevant lineage tip** and work against the per-commit
   DAG CI (`tests/ci_dag.sh`); each commit should build and test on its own.
3. **Open a PR.** A maintainer reviews; the review loop is the same DAG walk
   that every other commit goes through.
4. **Attribution** — because you retain ownership, your author line stays
   yours unless you choose otherwise.

## Conduct

Be generous, be direct, credit others' work as their own. We don't tolerate
harassment or bad-faith derailing.

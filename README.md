# usage — R2DP usage & spend context

A **meta branch**: it does not carry project source code. The actual R2DP
source lives on `main`. This branch holds the agent's usage accounting —
token spend, the user-message time-budget ledger, and the tooling that
produces them.

## Contents
- `usage/` — ledger + scripts (see `usage/README.md`).
- `README.md` — this file.

## Parallel context branches
| Branch | Purpose |
|---|---|
| `main` | the actual R2DP source + development |
| `lineage` | lineage DAG + memory cross-reference |
| `agent` | agent memory milestones ledger |
| `usage` | token-spend + user-message time-budget ledgers (this branch) |
| `site` | passive static site from the above |

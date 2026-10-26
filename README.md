# lineage — R2DP lineage tracking context

A **meta branch**: it does not carry project source code. The actual R2DP
source lives on `main`. This branch tracks the *lineage* of the main
development project — the commit DAG and how each node relates to the agent
context that explains it.

## Contents
- `docs/memory-links.md` — cross-references each lineage commit/branch to the
  agent-memory context (in `AGENT_MEMORY_MILESTONES.md` on `agent`).
- `README.md` — this file.

## Parallel context branches
| Branch | Purpose |
|---|---|
| `main` | the actual R2DP source + development |
| `lineage` | lineage DAG + memory cross-reference (this branch) |
| `agent` | agent memory milestones ledger |
| `usage` | token-spend + user-message time-budget ledgers |
| `site` | passive static site from the above |

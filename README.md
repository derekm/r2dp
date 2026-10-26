# agent — R2DP agent memory context

A **meta branch**: it does not carry project source code. The actual R2DP
source lives on `main`. This branch holds the agent's durable memory
milestones — the ledger of what the agent learned, compaction anchors, and
corrections applied while building R2DP.

## Contents
- `AGENT_MEMORY_MILESTONES.md` — the agent memory milestone ledger.
- `README.md` — this file.

## Parallel context branches
| Branch | Purpose |
|---|---|
| `main` | the actual R2DP source + development |
| `lineage` | lineage DAG + memory cross-reference |
| `agent` | agent memory milestones ledger (this branch) |
| `usage` | token-spend + user-message time-budget ledgers |
| `site` | passive static site from the above |

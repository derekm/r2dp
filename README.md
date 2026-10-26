# site — R2DP passive project site

A **meta branch**: it does not carry project source code. The actual R2DP
source lives on `main`. This branch holds the passive static-site generator
that consumes the parallel context branches (lineage, agent, usage, and the
contribution policy) and renders a static `index.html` for future Pages.

## Contents
- `site/gen_site.py` — stdlib-first static-site generator.
- `site/index.html` — the generated artifact.
- `.github/workflows/site.yml` — passive build + deploy to gh-pages.
- `README.md` — this file.

## Parallel context branches
| Branch | Purpose |
|---|---|
| `main` | the actual R2DP source + development |
| `lineage` | lineage DAG + memory cross-reference |
| `agent` | agent memory milestones ledger |
| `usage` | token-spend + user-message time-budget ledgers |
| `site` | passive static site from the above (this branch) |

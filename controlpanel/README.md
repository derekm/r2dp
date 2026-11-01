# r2dp meta-branch control panel (prototype)

A small web UI + backend to drive the repetitive meta-branch commands
(lineage / agent / usage / site) from a browser instead of only via the
Telegram agent.

## Top-10 commands exposed

| # | Command | Endpoint |
|---|---|---|
| 1 | List branches | `GET /api/branches` |
| 2 | Git status | `GET /api/status` |
| 3 | Branch file tree | `GET /api/branch/{b}/tree` |
| 4 | Commit log | `GET /api/branch/{b}/log?n=` |
| 5 | Show branch file | `GET /api/branch/{b}/file?path=` |
| 6 | Generate site | `POST /api/generate-site?confirm=1` |
| 7 | Refresh usage ledgers | `POST /api/refresh-usage?confirm=1` |
| 8 | Build all branches | `POST /api/build-all?confirm=1` |
| 9 | Create branch | `POST /api/branch/create?name=&base=&confirm=1` |
| 10 | Push branch | `POST /api/push?branch=&upstream=&confirm=1` |

## Run

```sh
python controlpanel/app.py          # or: run.py
# -> http://127.0.0.1:8123
```

FastAPI + uvicorn. `run.py` is a thin convenience launcher.

## Security model (prototype)

- Binds to **127.0.0.1 only** — not exposed to LAN/network.
- Read-only commands run immediately; **state-changing** commands (generate
  site, refresh usage, build, branch create, push) require `?confirm=1`.
- No secrets handled; user-message bodies are encrypted via the same
  out-of-repo key the CLI uses.
- This is a local dev panel, not production auth. If it ever goes on a real
  server, replace the confirm checkbox with real authentication and a
  command allow-list.

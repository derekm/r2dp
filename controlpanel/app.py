#!/usr/bin/env python3
"""r2dp meta-branch control panel — prototype backend.

A FastAPI app exposing the top-10 repetitive commands from the meta-branch
workstream (lineage/agent/usage/site) as HTTP endpoints, with a static
frontend served from ./public/.

Security model (prototype): the server binds to 127.0.0.1 only (no LAN
exposure).  Read-only commands run immediately; state-changing commands
(branch create, push, generate, refresh, build) require `?confirm=1` and
must not be pointed at a repo you don't expect.  No secrets are handled.

Run:  python app.py  -> http://127.0.0.1:8123
"""
import os
import shlex
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

REPO = Path(__file__).resolve().parent.parent  # repo root = one level up

app = FastAPI(title="r2dp meta-branch control panel")


def git(*args):
    # insert '--' before path-ish args when a revision could be ambiguous with
    # a file/dir name (e.g. branch `site` vs `site/`). We disambiguate by
    # placing '--' right before the first path argument of show/log/ls-tree.
    r = subprocess.run(["git", "-C", str(REPO), *args],
                       capture_output=True, text=True)
    return {"ok": r.returncode == 0, "out": r.stdout, "err": r.stderr}


def py(script, *args):
    r = subprocess.run(["python", str(script), *args], capture_output=True, text=True,
                       cwd=str(REPO))
    return {"ok": r.returncode == 0, "out": r.stdout, "err": r.stderr}


def must_confirm(confirm: bool, action: str):
    if not confirm:
        raise HTTPException(400, f"state-changing action '{action}' needs ?confirm=1")


# ---------------------------------------------------------------- read-only
@app.get("/api/branches")
def branches():
    """List branches with short SHA and latest subject."""
    r = git("for-each-ref", "--format=%(refname:short) %(objectname:short)",
            "refs/heads")
    rows = []
    for line in r["out"].splitlines():
        name, sha = line.split(" ", 1)
        lg = git("log", "-1", "--format=%s", name)["out"].strip()
        rows.append({"branch": name, "sha": sha, "subject": lg})
    rows.sort(key=lambda d: d["branch"])
    return {"ok": True, "branches": rows}


@app.get("/api/branch/{branch}/log")
def branch_log(branch: str, n: int = Query(20, ge=1, le=120)):
    # '--' separates the revision from any path that could collide with the
    # branch name (e.g. branch `site` vs the `site/` directory).
    r = git("log", f"-{n}", "--format=%h|%ad|%an|%s", "--date=short", branch, "--")
    if not r["ok"]:
        raise HTTPException(404, r["err"].strip() or f"no such branch {branch}")
    rows = []
    for line in r["out"].splitlines():
        parts = line.split("|", 3)
        if len(parts) == 4:
            rows.append({"sha": parts[0], "date": parts[1], "author": parts[2], "subject": parts[3]})
    return {"ok": True, "branch": branch, "commits": rows}


@app.get("/api/branch/{branch}/tree")
def branch_tree(branch: str):
    r = git("ls-tree", "--name-only", branch, "--")
    if not r["ok"]:
        raise HTTPException(404, r["err"].strip() or f"no such branch {branch}")
    return {"ok": True, "branch": branch, "files": [f for f in r["out"].splitlines() if f]}


@app.get("/api/branch/{branch}/file")
def branch_file(branch: str, path: str):
    r = git("show", f"{branch}:{path}")
    if not r["ok"]:
        raise HTTPException(404, r["err"].strip() or "path not found")
    return {"ok": True, "branch": branch, "path": path, "content": r["out"]}


@app.get("/api/status")
def status():
    r = git("status", "-sb")
    return {"ok": True, "out": r["out"]}


# ------------------------------------------------------------- mutating
@app.post("/api/generate-site")
def generate_site(confirm: bool = Query(False)):
    must_confirm(confirm, "generate-site")
    r = py(REPO / "site" / "gen_site.py", str(REPO / "site" / "index.html"))
    return {"ok": r["ok"], "out": r["out"], "err": r["err"]}


@app.post("/api/refresh-usage")
def refresh_usage(confirm: bool = Query(False)):
    must_confirm(confirm, "refresh-usage")
    results = {}
    # normalize (cron audit)
    results["normalize"] = py(REPO / "usage" / "normalize.py",
                              str(REPO / "usage" / "raw" / "usage_audit.jsonl"),
                              str(REPO / "usage"))
    # session extractor
    results["extract_state"] = py(REPO / "usage" / "extract_state_usage.py")
    # user messages (encrypted bodies, key via env if present)
    env = dict(os.environ)
    kf = os.environ.get("R2DP_LEDGER_KEYFILE") or os.path.join(
        os.path.expandvars("%LOCALAPPDATA%"), "hermes", "r2dp_ledger.key")
    if os.path.exists(kf):
        env["R2DP_LEDGER_KEYFILE"] = kf
    results["user_messages"] = py(REPO / "usage" / "user_messages.py")
    return {"ok": True, "results": results}


@app.post("/api/build-all")
def build_all(confirm: bool = Query(False)):
    must_confirm(confirm, "build-all")
    r = py(REPO / "ci" / "ci_all_branches.sh")
    tail = "\n".join(r["out"].splitlines()[-30:])
    return {"ok": r["ok"], "out": tail, "err": r["err"]}


@app.post("/api/branch/create")
def branch_create(name: str, base: str = "main", confirm: bool = Query(False)):
    must_confirm(confirm, "branch-create")
    if not name or "/" in name or " " in name:
        raise HTTPException(400, "invalid branch name")
    r = git("checkout", "-b", name, base)
    return {"ok": r["ok"], "out": r["out"], "err": r["err"]}


@app.post("/api/push")
def push(branch: str, upstream: bool = Query(False), confirm: bool = Query(False)):
    must_confirm(confirm, "push")
    args = ["push"]
    if upstream:
        args += ["-u"]
    args += ["origin", branch]
    r = git(*args)
    return {"ok": r["ok"], "out": r["out"], "err": r["err"]}


# ====================================================================
# Main-project ClickOps: build/test/demo/bench/e2e on the source (main).
# All run via meson or the repo's own scripts. Mutating builds run on a
# throwaway checkout so the live worktree is never disturbed.
# ====================================================================
MAIN_WS = Path(os.environ.get("R2DP_CLICKOPS_WS", os.path.join(
    str(Path.home() if os.name != "nt" else os.environ.get("TEMP", ".")),
    "r2dp-clickops-ws")))


def _worktree_main():
    """Check out main into the ClickOps workspace (fresh), via git worktree."""
    ws = MAIN_WS
    import shutil
    if ws.exists():
        subprocess.run(["git", "-C", str(REPO), "worktree", "remove",
                        "--force", str(ws)],
                       capture_output=True, text=True)
        shutil.rmtree(str(ws), ignore_errors=True)
    subprocess.run(["git", "-C", str(REPO), "worktree", "add", "--detach",
                    "--force", str(ws), "main"],
                   capture_output=True, text=True)
    ws.mkdir(parents=True, exist_ok=True)
    return ws


def _ensure_ws():
    if not (MAIN_WS / "meson.build").exists():
        _worktree_main()
    return MAIN_WS


def clickops(argv, ws, timeout=60):
    """Run a full argv in the ClickOps worktree; return {ok,out,err}.
    Resolves the tool via shutil.which (searching PATH plus the active Python
    venv's Scripts dir, where meson/ninja live when pip-installed)."""
    import shutil
    cmd = list(argv)
    # include the venv Scripts dir in the search path for meson/ninja
    venv_scripts = os.path.join(os.path.dirname(sys.executable), "Scripts")
    search = [venv_scripts] + os.environ.get("PATH", "").split(os.pathsep)
    exe = shutil.which(cmd[0], path=os.pathsep.join(search)) or cmd[0]
    env = dict(os.environ)
    if venv_scripts and venv_scripts not in env.get("PATH", ""):
        env["PATH"] = venv_scripts + os.pathsep + env.get("PATH", "")
    r = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True,
                       cwd=str(ws), env=env, timeout=timeout)
    return {"ok": r.returncode == 0, "out": r.stdout[-8000:], "err": r.stderr[-8000:]}


def _main_status(ws):
    return {"ws": str(ws), "exists": ws.exists(),
            "has_meson": (ws / "meson.build").exists()}


@app.post("/api/main/checkout")
def main_checkout(confirm: bool = Query(False)):
    must_confirm(confirm, "main-checkout")
    ws = _worktree_main()
    return {"ok": True, **_main_status(ws)}


@app.post("/api/main/setup")
def main_setup(confirm: bool = Query(False)):
    must_confirm(confirm, "main-setup")
    ws = _ensure_ws()
    r = clickops(["meson", "setup", "build"], ws)
    return {"ok": r["ok"], "out": r["out"], "err": r["err"], **_main_status(ws)}


@app.post("/api/main/build")
def main_build(confirm: bool = Query(False)):
    must_confirm(confirm, "main-build")
    ws = _ensure_ws()
    clickops(["meson", "setup", "build"], ws)
    r = clickops(["meson", "compile", "-C", "build"], ws)
    return {"ok": r["ok"], "out": r["out"], "err": r["err"], **_main_status(ws)}


@app.post("/api/main/test")
def main_test(confirm: bool = Query(False)):
    must_confirm(confirm, "main-test")
    ws = _ensure_ws()
    if not (ws / "build").exists():
        clickops(["meson", "setup", "build"], ws)
    r = clickops(["meson", "test", "-C", "build", "--print-errorlogs"], ws, timeout=300)
    return {"ok": r["ok"], "out": r["out"], "err": r["err"], **_main_status(ws)}


@app.post("/api/main/sanitize")
def main_sanitize(confirm: bool = Query(False)):
    must_confirm(confirm, "main-sanitize")
    ws = _ensure_ws()
    r = clickops(
        ["meson", "setup", "build-asan", "--buildtype=debug",
         "-Db_sanitize=address,undefined", "-Db_lundef=false", "-Db_staticpic=false"],
        ws)
    r2 = clickops(["meson", "compile", "-C", "build-asan"], ws)
    r3 = clickops(["meson", "test", "-C", "build-asan", "--print-errorlogs"], ws, timeout=300)
    return {"ok": r3["ok"], "out": r2["out"] + r3["out"], "err": r3["err"], **_main_status(ws)}


@app.post("/api/main/dpdk")
def main_dpdk(confirm: bool = Query(False)):
    must_confirm(confirm, "main-dpdk")
    ws = _ensure_ws()
    r = clickops(
        ["meson", "setup", "build-dpdk", "--buildtype=debugoptimized", "-Denable_dpdk=enabled"],
        ws)
    r2 = clickops(["meson", "compile", "-C", "build-dpdk"], ws)
    return {"ok": r["ok"], "out": r2["out"], "err": r2["err"], **_main_status(ws)}


@app.post("/api/main/bench")
def main_bench(confirm: bool = Query(False)):
    must_confirm(confirm, "main-bench")
    ws = _ensure_ws()
    if not (ws / "build").exists():
        clickops(["meson", "setup", "build"], ws)
    exe = ws / "build" / "bench" / "fwd_bench"
    if not exe.exists():
        clickops(["meson", "compile", "-C", "build"], ws)
    r = subprocess.run([str(exe)], capture_output=True, text=True, cwd=str(ws), timeout=120)
    return {"ok": r.returncode == 0, "out": r.stdout[-4000:], "err": r.stderr[-4000:],
            **_main_status(ws)}


@app.post("/api/main/e2e")
def main_e2e(confirm: bool = Query(False)):
    must_confirm(confirm, "main-e2e")
    ws = _ensure_ws()
    if not (ws / "build").exists():
        clickops(["meson", "setup", "build"], ws)
    # the repo ships an IKE e2e harness; run it if root+tools present
    r = clickops(["bash", "ike_e2e.sh"], ws, timeout=300)
    return {"ok": r["ok"], "out": r["out"], "err": r["err"], **_main_status(ws)}


@app.post("/api/main/milestones")
def main_milestones(confirm: bool = Query(False)):
    must_confirm(confirm, "main-milestones")
    md = git("show", "main:MILESTONES.md")
    return {"ok": True, "out": md["out"][:8000], "ws": str(MAIN_WS), "exists": MAIN_WS.exists()}


@app.get("/api/main/status")
def main_status_api():
    return {"ok": True, **_main_status(MAIN_WS)}


# ---------------------------------------------------------------- static
public_dir = Path(__file__).resolve().parent / "public"
app.mount("/", StaticFiles(directory=str(public_dir), html=True), name="public")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8123, reload=False)

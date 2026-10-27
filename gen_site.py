#!/usr/bin/env python3
"""Passive static site generator for the r2dp project.

Consumes the three content branches (lineage, agent, usage) and renders a
single self-contained static HTML file (site/index.html).  Works passively:
it only reads the current checkout's view of the branches (via `git show`)
and writes one artifact — no network, no build deps beyond the stdlib.

Sections rendered:
  - Overview  : project description + contribution policy
  - Lineage   : the commit DAG (zip1 M0 -> zip2 M0+M1 -> ...) with per-commit
                docs and the memory-links cross-reference
  - Agent     : the agent memory milestones ledger
  - Usage     : token-spend + user-message time-budget ledgers
  - Milestone map

Usage: python3 gen_site.py [outfile]
Default outfile: site/index.html (repo-relative).
"""
import html
import io
import os
import re
import subprocess
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)


def git(*args):
    """Run git in the repo root, return stdout (may be empty on error)."""
    try:
        return subprocess.run(["git", "-C", REPO_ROOT, *args],
                              capture_output=True, text=True, check=False).stdout
    except Exception:
        return ""


def branch_sha(branch):
    s = git("rev-parse", "--short", branch).strip()
    return s if s else "?"


def h(txt):
    return html.escape(txt or "")


def para(txt):
    """Escape and wrap preformatted/intro text in <p>."""
    return f"<p>{h(txt)}</p>"


def section(title, body, anchor):
    return f'<section id="{anchor}"><h2>{h(title)}</h2>{body}</section>\n'


def render_lineage():
    # Walk HEAD's ancestry on the lineage branch (via git log --all --simplify).
    log = git("log", "--format=%h|%ad|%an|%s", "--date=short", "--all",
              "--simplify-by-decoration", "-120")
    rows = []
    for line in log.splitlines():
        parts = line.split("|", 3)
        if len(parts) != 4:
            continue
        short_sha, date, author, subject = parts
        rows.append(
            f"<li><code>{h(short_sha)}</code> <b>{h(author)}</b> "
            f"<span class='date'>({h(date)})</span> — {h(subject)}</li>")
    body = "<ul class='dag'>" + "\n".join(rows) + "</ul>" if rows else para("(no lineage history)")
    return section("Lineage DAG", body, "lineage")


def render_branch_doc(branch, path, fallback=""):
    content = git("show", f"{branch}:{path}")
    if not content:
        return para(f"({fallback})")
    # render as <pre> blocks (plain text is fine for a static site)
    return f"<pre class='doc'>{h(content.strip())}</pre>"


def render_usage_tsv(branch, path):
    content = git("show", f"{branch}:{path}")
    if not content:
        return para("(no usage table)")
    out = ["<table><thead><tr>"]
    lines = content.strip().splitlines()
    if not lines:
        return para("(empty)")
    headers = lines[0].split("\t")
    out.append("<tr>" + "".join(f"<th>{h(c)}</th>" for c in headers) + "</tr>")
    out.append("</thead><tbody>")
    for line in lines[1:]:
        cells = line.split("\t")
        out.append("<tr>" + "".join(f"<td>{h(c)}</td>" for c in cells) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def _markdown_to_html(md: str, body_only: bool = True) -> str:
    """Convert markdown to HTML.  Uses the `markdown` package when present
    (proper parsing of headings, lists, emphasis, code); falls back to a
    minimal stdlib renderer that handles headings, lists, emphasis, code
    spans and paragraphs."""
    try:
        import markdown as mdlib  # type: ignore
        return mdlib.markdown(md, extensions=["extra"])
    except Exception:
        return _stdlib_markdown(md)


def _stdlib_markdown(md: str) -> str:
    """Minimal markdown subset renderer (stdlib only), used only when the
    `markdown` package is unavailable.  Handles the constructs used in the
    milestone map: ATX headings, bullet/numbered lists, fenced/code spans,
    bold/emphasis, inline code backticks, and paragraphs."""
    out = []
    in_list = False
    in_pre = False
    pre_buf = []
    for raw in md.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            if in_pre:
                out.append("<pre><code>" + h("\n".join(pre_buf)) + "</code></pre>")
                pre_buf, in_pre = [], False
            else:
                in_pre = True
            continue
        if in_pre:
            pre_buf.append(line)
            continue

        def inline(t):
            # escape, then apply inline code, then emphasis
            t = h(t)
            # inline code `x`
            t = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", t)
            # **bold**
            t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
            # *italic*
            t = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", t)
            return t

        if line.startswith("###"):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h4>{inline(line[3:].strip())}</h4>")
        elif line.startswith("##"):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h3>{inline(line[2:].strip())}</h3>")
        elif line.startswith("# "):
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<h2>{inline(line[1:].strip())}</h2>")
        elif re.match(r"^\s*([-*])\s+", line) or re.match(r"^\s*\d+[.)]\s+", line):
            if not in_list:
                out.append("<ul>"); in_list = True
            item = re.sub(r"^\s*([-*]|\d+[.)])\s+", "", line)
            out.append("<li>" + inline(item) + "</li>")
        elif line.strip():
            if in_list: out.append("</ul>"); in_list = False
            out.append(f"<p>{inline(line.strip())}</p>")
    if in_list: out.append("</ul>")
    if in_pre: out.append("<pre><code>" + h("\n".join(pre_buf)) + "</code></pre>")
    return "".join(out)


def render_milestones():
    md = git("show", "lineage:docs/MILESTONES.md") or git("show", "lineage:MILESTONES.md") \
        or git("show", "usage:docs/MILESTONES.md")
    if not md:
        return para("(no milestone map)")
    body = _markdown_to_html(md)
    return section("Milestone Map", body, "milestones")


def render_overview():
    readme = git("show", "lineage:README.md") or "R2DP: racoon2 external dataplane control protocol."
    first = readme.splitlines()[0] if readme.splitlines() else ""
    body = para(first)
    body += para("External dataplane control protocol for racoon2: drives a "
                 "DPDK forwarder instead of the kernel via a PF_KEY-shaped "
                 "protocol on a unix socket. Contributors own their work; "
                 "contributions license its use to generate derivative output.")
    contrib = git("show", "contrib-doc:CONTRIBUTING.md")
    if contrib:
        body += "<h3>Contribution policy</h3><pre class='doc'>" + h(contrib.strip()[:1500]) + "</pre>"
    return section("Overview", body, "overview")


def render_nav():
    return ("<nav><a href='#overview'>Overview</a> · "
            "<a href='#lineage'>Lineage DAG</a> · "
            "<a href='#agent'>Agent memory</a> · "
            "<a href='#usage'>Usage</a> · "
            "<a href='#milestones'>Milestones</a></nav>")


def main():
    outfile = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "site", "index.html")
    os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)

    trunk = "".join([
        render_overview(),
        render_lineage(),
        section("Agent memory milestones", render_branch_doc(
            "agent", "AGENT_MEMORY_MILESTONES.md", "agent ledger"), "agent"),
        section("Lineage ↔ Agent memory links", render_branch_doc(
            "lineage", "docs/memory-links.md", "memory links"), "links"),
        section("Usage — token spend", render_usage_tsv(
            "usage", "usage/aggregate_by_model_sessions.tsv"), "usage-token"),
        section("Usage — user-message budget", render_usage_tsv(
            "usage", "usage/user_messages_by_principal.tsv"), "usage-msg"),
        render_milestones(),
    ])

    html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>R2DP — external dataplane control protocol for racoon2</title>
<style>
 body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#1a1a1a;background:#fdfdfd}}
 nav a{{margin-right:.75rem;color:#0366d6;text-decoration:none}}
 section{{margin:2rem 0;padding:1rem 0;border-top:1px solid #e1e4e8}}
 h1,h2,h3{{line-height:1.2}}
 h2{{border-bottom:2px solid #0366d6;padding-bottom:.25rem}}
 .dag li{{margin:.35rem 0}}
 .date{{color:#888;font-size:.9em}}
 pre.doc{{background:#f6f8fa;padding:1rem;border-radius:6px;overflow:auto;font-size:.85em}}
 table{{border-collapse:collapse;width:100%;font-size:.9em}}
 th,td{{border:1px solid #e1e4e8;padding:.35rem .5rem;text-align:left}}
 th{{background:#f6f8fa}}
 footer{{margin-top:3rem;color:#888;font-size:.85em;border-top:1px solid #e1e4e8;padding-top:1rem}}
</style></head>
<body>
<h1>R2DP — external dataplane control protocol for racoon2</h1>
{render_nav()}
{trunk}
<footer>Generated passively by <code>site/gen_site.py</code> from the
<code>lineage</code>, <code>agent</code>, and <code>usage</code> branches.
Branches at build: lineage={h(branch_sha('lineage'))}, agent={h(branch_sha('agent'))},
usage={h(branch_sha('usage'))}, contrib-doc={h(branch_sha('contrib-doc'))}.</footer>
</body></html>
"""
    with open(outfile, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    print(f"wrote {outfile} ({os.path.getsize(outfile)} bytes)")


if __name__ == "__main__":
    main()

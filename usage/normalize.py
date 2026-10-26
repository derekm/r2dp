#!/usr/bin/env python3
"""Regenerate usage aggregates from the raw audit JSONL.

Reads raw/usage_audit.jsonl (one JSON object per line, as written by the
Hermes cron audit), writes aggregate_by_model.tsv and aggregate_by_day.tsv.

Canonical path for refreshing the usage branch:
    python3 normalize.py [RAW | -] [OUTDIR]
"""
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    raw = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "raw", "usage_audit.jsonl")
    out = sys.argv[2] if len(sys.argv) > 2 else HERE

    rows = []
    with open(raw, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))

    ok = [r for r in rows if r.get("total_tokens")]
    print(f"entries: {len(rows)}  with tokens: {len(ok)}")

    by_model = defaultdict(lambda: [0, 0, 0])   # runs, tokens, seconds
    for r in ok:
        m = r["model"]
        by_model[m][0] += 1
        by_model[m][1] += r["total_tokens"]
        by_model[m][2] += (r.get("duration_ms") or 0) / 1000.0

    with open(os.path.join(out, "aggregate_by_model.tsv"), "w", encoding="utf-8") as fh:
        fh.write("model\truns\ttotal_tokens\tduration_s\n")
        for m in sorted(by_model, key=lambda k: -by_model[k][1]):
            n, t, d = by_model[m]
            fh.write(f"{m}\t{n}\t{t}\t{d:.0f}\n")

    by_day = defaultdict(lambda: [0, 0])
    for r in ok:
        day = r["ts"][:10]
        by_day[day][0] += 1
        by_day[day][1] += r["total_tokens"]

    with open(os.path.join(out, "aggregate_by_day.tsv"), "w", encoding="utf-8") as fh:
        fh.write("date\truns\ttotal_tokens\n")
        for day in sorted(by_day):
            n, t = by_day[day]
            fh.write(f"{day}\t{n}\t{t}\n")

    print(f"wrote aggregate_by_model.tsv ({len(by_model)} models), "
          f"aggregate_by_day.tsv ({len(by_day)} days) to {out}")


if __name__ == "__main__":
    main()

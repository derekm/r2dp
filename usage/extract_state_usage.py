#!/usr/bin/env python3
"""Extract interactive-session token usage from Hermes state.db.

Complements raw/usage_audit.jsonl (cron-job runs only) with the per-session
accounting recorded in the runtime SQLite store.  Together the two sources
cover both scheduled background jobs and interactive/agent session turns.

Writes:
  raw/state_session_usage.tsv         - one row per session_model_usage row
  aggregate_by_model_sessions.tsv     - totals grouped by model
  aggregate_by_day_sessions.tsv       - totals grouped by day (first_seen)

Usage: python3 extract_state_usage.py [STATE_DB] [OUTDIR]
(Default STATE_DB: the Hermes runtime state.db; pass - to skip live read and
 just re-emit from an existing raw TSV.)
"""
import csv
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    db = sys.argv[1] if len(sys.argv) > 1 else os.path.expandvars(
        r"%LOCALAPPDATA%\hermes\state.db")
    out = sys.argv[2] if len(sys.argv) > 2 else HERE
    os.makedirs(os.path.join(out, "raw"), exist_ok=True)

    if db == "-" or not os.path.exists(db):
        rawtsv = os.path.join(HERE, "raw", "state_session_usage.tsv")
        print(f"reading existing raw: {rawtsv}")
        rows = list(csv.DictReader(open(rawtsv, encoding="utf-8"), delimiter="\t"))
    else:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        cols = [c[1] for c in con.execute("PRAGMA table_info(session_model_usage)")]
        rows = [dict(zip(cols, r)) for r in con.execute(
            "SELECT * FROM session_model_usage")]
        with open(os.path.join(out, "raw", "state_session_usage.tsv"), "w",
                  encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        print(f"read {len(rows)} rows from state.db -> raw/state_session_usage.tsv")

    def num(r, k):
        try:
            return int(r.get(k) or 0)
        except (TypeError, ValueError):
            return 0

    # by model
    from collections import defaultdict
    m = defaultdict(lambda: [0, 0, 0, 0, 0])  # calls, in, out, cache_read, reason
    for r in rows:
        mod = r.get("model") or "?"
        m[mod][0] += num(r, "api_call_count")
        m[mod][1] += num(r, "input_tokens")
        m[mod][2] += num(r, "output_tokens")
        m[mod][3] += num(r, "cache_read_tokens")
        m[mod][4] += num(r, "reasoning_tokens")
    with open(os.path.join(out, "aggregate_by_model_sessions.tsv"), "w",
              encoding="utf-8") as fh:
        fh.write("model\tapi_calls\tinput_tokens\toutput_tokens\tcache_read_tokens\treasoning_tokens\n")
        for mod in sorted(m, key=lambda k: -m[k][1]):
            c = m[mod]
            fh.write(f"{mod}\t{c[0]}\t{c[1]}\t{c[2]}\t{c[3]}\t{c[4]}\n")

    # by day (first_seen)
    import datetime
    d = defaultdict(lambda: [0, 0, 0])
    for r in rows:
        fs = r.get("first_seen")
        if not fs:
            continue
        try:
            day = datetime.datetime.utcfromtimestamp(float(fs)).strftime("%Y-%m-%d")
        except (TypeError, ValueError):
            continue
        d[day][0] += num(r, "api_call_count")
        d[day][1] += num(r, "input_tokens")
        d[day][2] += num(r, "output_tokens")
    with open(os.path.join(out, "aggregate_by_day_sessions.tsv"), "w",
              encoding="utf-8") as fh:
        fh.write("date\tapi_calls\tinput_tokens\toutput_tokens\n")
        for day in sorted(d):
            c = d[day]
            fh.write(f"{day}\t{c[0]}\t{c[1]}\t{c[2]}\n")

    tot_in = sum(num(r, "input_tokens") for r in rows)
    tot_out = sum(num(r, "output_tokens") for r in rows)
    tot_calls = sum(num(r, "api_call_count") for r in rows)
    print(f"calls={tot_calls:,} input={tot_in:,} output={tot_out:,}")


if __name__ == "__main__":
    main()

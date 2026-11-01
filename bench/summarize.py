#!/usr/bin/env python3
"""Summarize a bench/run.sh result directory: summary.csv + summary.md."""
import csv, glob, json, os, sys

out = sys.argv[1]
env = json.load(open(os.path.join(out, "env.json")))
rows = []
for f in sorted(glob.glob(os.path.join(out, "fwd_w*.json"))):
    j = json.load(open(f))
    w = j.get("workers", 1)
    for r in j["results"]:
        for d in ("enc", "dec"):
            mpps = r[d + "_mpps"]
            rows.append({"bench": "fwd_bench", "dir": d, "workers": r.get("workers", w),
                         "tunnels": r.get("tunnels", ""), "size": r["size"],
                         "mpps": round(mpps, 3),
                         "gbps": round(mpps * r["size"] * 8 / 1e3, 2),
                         "cyc_pkt": r.get(d + "_cyc_pkt", ""), "loss": ""})
ef = os.path.join(out, "e2e.jsonl")
if os.path.exists(ef):
    for line in open(ef):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        rows.append({"bench": "e2e", "dir": "A->B", "workers": r["workers"],
                     "tunnels": r["tunnels"], "size": r["size"],
                     "mpps": r.get("nl_mpps", r.get("valid_mpps")),
                     "gbps": r.get("nl_gbps", r.get("gbps")),
                     "cyc_pkt": "", "loss": r.get("nl_loss", r.get("loss")),
                     "sat_gbps": r.get("sat_gbps", "")})
keys = ["bench", "dir", "workers", "tunnels", "size", "mpps", "gbps",
        "cyc_pkt", "loss", "sat_gbps"]
with open(os.path.join(out, "summary.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, keys, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
md = [f"# r2dp benchmark {env['date_utc']}", "",
      f"git `{env['git']}`{' (dirty)' if env['dirty'] else ''} | {env['cpu_model']} | "
      f"{env['ncpu']} CPUs ({env['cpus_used']}) | {env['kernel']} | DPDK {env['dpdk']} | "
      f"PMD {env['pmd']} | hugepages {'yes' if env['hugepages'] else 'no (--no-huge)'}", "",
      "fwd_bench: one data-path call loop per worker, sizes are inner IPv4 bytes, "
      "Gbps of inner packets.  e2e: zero-loss (<= LOSS) rate through two "
      "forwarders, sizes are Ethernet frame bytes; sat = saturated.", "",
      "| bench | dir | workers | tunnels | size | Mpps | Gbps | cyc/pkt | sat Gbps |",
      "|---|---|---|---|---|---|---|---|---|"]
for r in rows:
    md.append("| {bench} | {dir} | {workers} | {tunnels} | {size} | {mpps} | {gbps} | "
              "{cyc_pkt} | {sat} |".format(sat=r.get("sat_gbps", ""), **r))
open(os.path.join(out, "summary.md"), "w").write("\n".join(md) + "\n")
print("\n".join(md))

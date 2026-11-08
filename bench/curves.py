#!/usr/bin/env python3
"""Regenerate bench/curves.png from benchmark data.

Two modes:

  bench/curves.py plot [--data bench/curves_data.json]
      Render curves.png from the committed data JSON (works offline).

  bench/curves.py collect --bin /path/fwd_bench --box NAME --pmd openssl|aesni_mb \
          --hz 3.19e9 --workers 1,2,4,8,11 --size 64
      Run fwd_bench --json for each worker count and merge the enc/dec Mpps
      into --data (default bench/curves_data.json).  --box is any label
      (e.g. ".179 (12-core)") used as a series name.

  bench/curves.py collect --from-json fwd_res.json --box NAME --pmd PMD
      Parse an existing fwd_bench --json file instead of re-running.

The P4 tap-free point and the tap-path values are read from the data JSON's
"p4" / "tap" keys (committed from R2DP_P4_BENCH and bench/p4_bench.sh runs).

Data schema (curves_data.json):
{
  "dpdk": [ {"box": "...", "pmd": "openssl", "size": 64, "hz": 3.19e9,
             "enc": {worker: mpps, ...}, "dec": {...},
             "enc_cyc": {worker: cyc/pkt}, "dec_cyc": {...}}, ... ],
  "p4":   {"tapless_mpps": 1.00, "tap_mpps": 0.132, "dpdk_tap_mpps": 0.252,
           "note": "..."},
}
"""
import argparse, json, os, subprocess, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DEFAULT_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "curves_data.json")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "curves.png")


def load_data(path):
    if not os.path.exists(path):
        return {"dpdk": [], "p4": {}}
    with open(path) as f:
        return json.load(f)


def save_data(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=1, sort_keys=False)
    print(f"wrote {path}")


def parse_fwd_json(text):
    """Parse one or more concatenated fwd_bench --json blobs (one per run)
    into a flat list of rows {'pmd','workers','size',
    enc,dec,enc_cyc,dec_cyc}.  --json - yields one JSON object per run on
    stdout; workers default to 1 on the single-worker path (the object omits
    the field).  Rows carry the bench's own per-worker cycles/pkt and Mpps."""
    import json as _json
    dec = _json.JSONDecoder()
    text = text[text.find("{"):]
    rows = []
    while text.strip():
        obj, end = dec.raw_decode(text)
        text = text[end:].lstrip()
        w = obj.get("workers", 1)
        for r in obj.get("results", []):
            rows.append({
                "pmd": obj.get("pmd", "?"),
                "workers": r.get("workers", w),
                "size": r.get("size"),
                "enc": r.get("enc_mpps"),
                "dec": r.get("dec_mpps"),
                "enc_cyc": r.get("enc_cyc_pkt"),
                "dec_cyc": r.get("dec_cyc_pkt"),
            })
    return rows


def collect_from_bin(data, args):
    path, box, pmd = args.bin, args.box, args.pmd
    hz = float(args.hz)
    ws = [int(x) for x in args.workers.split(",")]
    size = int(args.size)
    src = None
    for s in data.get("dpdk", []):
        if s["box"] == box and s["pmd"] == pmd:
            src = s
            break
    if src is None:
        src = {"box": box, "pmd": pmd, "size": size,
               "hz": hz, "enc": {}, "dec": {}, "enc_cyc": {}, "dec_cyc": {}}
        data["dpdk"].append(src)
    src.setdefault("enc_cyc", {})
    src.setdefault("dec_cyc", {})
    src["size"], src["hz"] = size, hz
    for w in ws:
        cmd = [path, "--pmd", pmd, "--sizes", str(size), "--tunnels", "1",
               "--runs", str(args.runs), "--workers", str(w),
               "--json", "-"]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode not in (0, 77):
            tail = p.stderr.strip().splitlines()[-1] if p.stderr.strip() else ""
            print(f"  W={w}: rc={p.returncode}: {tail}")
            continue
        rows = parse_fwd_json(p.stdout)
        for r in rows:
            if r["size"] == size:
                src["enc"][str(w)] = float(r["enc"])
                src["dec"][str(w)] = float(r["dec"])
                if r["enc_cyc"]:
                    src["enc_cyc"][str(w)] = float(r["enc_cyc"])
                if r["dec_cyc"]:
                    src["dec_cyc"][str(w)] = float(r["dec_cyc"])
        print(f"  W={w}: enc={src['enc'].get(str(w))} dec={src['dec'].get(str(w))} "
              f"{pmd} {box}")
    return data


def collect_from_file(data, args):
    with open(args.from_json) as f:
        rows = parse_fwd_json(f.read())
    # locate or create the series for this box/pmd, then overlay each worker
    src = next((s for s in data.get("dpdk", [])
                if s["box"] == args.box and s["pmd"] == args.pmd), None)
    fresh = src is None
    if fresh:
        src = {"box": args.box, "pmd": args.pmd, "enc": {}, "dec": {},
               "enc_cyc": {}, "dec_cyc": {}}
        data["dpdk"].append(src)
    src.setdefault("enc_cyc", {})
    src.setdefault("dec_cyc", {})
    for r in rows:
        src["enc"][str(r["workers"])] = r["enc"]
        src["dec"][str(r["workers"])] = r["dec"]
        if r["enc_cyc"]:
            src["enc_cyc"][str(r["workers"])] = r["enc_cyc"]
        if r["dec_cyc"]:
            src["dec_cyc"][str(r["workers"])] = r["dec_cyc"]
    if rows:
        src["size"] = rows[0]["size"]
    if args.hz:
        src["hz"] = float(args.hz)
    if not fresh:
        print(f"  merged {len(rows)} row(s) into {args.box} {args.pmd} "
              f"(enc keys now {sorted(src['enc'])})")
    return data


def plot(data, out):
    dpdk = sorted(data.get("dpdk", []),
                  key=lambda s: (s["pmd"] != "aesni_mb", "165" not in s["box"]))
    p4 = data.get("p4", {})
    p4_tapfree = p4.get("tapless_mpps", 1.00)
    p4_tap = p4.get("tap_mpps", 0.132)
    dpdk_tap = p4.get("dpdk_tap_mpps", 0.252)

    fig = plt.figure(figsize=(13.5, 10))
    gs = fig.add_gridspec(2, 2, height_ratios=[1.2, 1])

    # (a) DPDK tap-free scaling (enc) per series
    ax = fig.add_subplot(gs[0, :])
    styles = {"openssl": "o-", "aesni_mb": "^-"}
    for s in dpdk:
        xs = sorted(int(k) for k in s["enc"])
        label = f"{s['box']} {s['pmd']}"
        ax.plot(xs, [s["enc"][str(x)] for x in xs], styles.get(s["pmd"], "o-"),
                label=label, ms=6)
    ax.axhline(p4_tapfree, color="gray", ls=":", lw=1.5,
               label=f"P4 single instance (tap-free ~{p4_tapfree:.2f})")
    ax.axvspan(7.6, 12, color="green", alpha=0.07)
    ylo, yhi = ax.get_ylim()
    ax.text(8.1, ylo + (yhi - ylo) * 0.06,
            "PMD sized past the 8-QP default (max_nb_queue_pairs) -> W>8 runs",
            fontsize=8, color="green", va="bottom")
    ax.set_xlabel("packet workers (-n)")
    ax.set_ylabel("encrypt Mpps (tap-free, 64B)")
    ax.set_title("DPDK dataplane scaling - both boxes, both crypto PMDs (fwd_bench)")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="upper left")

    # (b) efficiency: the bench's measured per-worker enc cyc/pkt (its own
    # column), not aggregate Mpps turned into a fake cyc/pkt.
    ax = fig.add_subplot(gs[1, 0])
    for s in dpdk:
        if not s.get("enc_cyc"):
            continue  # collected before cyc/pkt was kept; nothing honest to plot
        xs = sorted(int(k) for k in s["enc_cyc"])
        ax.plot(xs, [s["enc_cyc"][str(x)] for x in xs],
                styles.get(s["pmd"], "o-"),
                label=f"{s['box']} {s['pmd']}", ms=6)
    ax.set_xlabel("packet workers (-n)")
    ax.set_ylabel("enc cyc/pkt (per-worker, lower=better)")
    ax.set_title("Per-worker efficiency (fwd_bench enc_cyc_pkt)")
    ax.grid(True, alpha=0.3)
    ax.legend()

    # (c) tap-free vs real-I/O: BOTH engines tap-free AND tap
    ax = fig.add_subplot(gs[1, 1])
    # representative DPDK tap-free points: W=1 openssl .165, W=1 aesni .179
    dpdk_tapfree = {}
    for s in dpdk:
        if "1" in s["enc"]:
            pm = "aesni" if s["pmd"] == "aesni_mb" else s["pmd"]
            box = "12c" if "179" in s["box"] else "4c"
            dpdk_tapfree[f"DPDK {box} {pm}"] = s["enc"]["1"]
    labels = ["P4 tap-free"] + list(dpdk_tapfree) + ["P4 net_tap", "DPDK net_tap"]
    vals = [p4_tapfree] + list(dpdk_tapfree.values()) + [p4_tap, dpdk_tap]
    colors = (["#4C72B0"] + ["#55A868"]*len(dpdk_tapfree) + ["#4C72B0", "#DD8452"])
    ax.bar(labels, vals, color=colors)
    for i, v in enumerate(vals):
        # honest label: axis is Mpps, so a 1.00 value is "1.00", NOT "1000K"
        ax.text(i, v, f"{v:.2f}" if v >= 1 else f"{v*1e3:.0f}K",
                ha="center", va="bottom", fontsize=9)
    ax.set_ylabel("Mpps")
    ax.set_title("Tap-free dataplane vs real I/O via shared net_tap (64B)")
    ax.grid(True, axis="y", alpha=0.3)
    plt.setp(ax.get_xticklabels(), rotation=20, ha="right")

    fig.suptitle("r2dp dataplane performance - measured, both engines, both boxes, all PMDs",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(out, dpi=110)
    print(f"wrote {out}")
    if p4.get("note"):
        print("note:", p4["note"])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=DEFAULT_DATA)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plot")
    p.set_defaults(func=plot)

    c = sub.add_parser("collect")
    c.add_argument("--bin", help="path to fwd_bench binary")
    c.add_argument("--from-json", help="existing fwd_bench --json file")
    c.add_argument("--box", required=True, help="series label, e.g. '.179 (12-core)'")
    c.add_argument("--pmd", required=True, choices=["openssl", "aesni_mb"])
    c.add_argument("--workers", default="1,2,4,8,11")
    c.add_argument("--size", default=64)
    c.add_argument("--hz", default=None, help="TSC hz for this box")
    c.add_argument("--runs", default=3)
    c.set_defaults(func=None)

    args = ap.parse_args()
    data = load_data(args.data)

    if args.cmd == "collect":
        if args.bin:
            collect_from_bin(data, args)
        elif args.from_json:
            collect_from_file(data, args)
        else:
            ap.error("collect needs --bin or --from-json")
        save_data(args.data, data)
    else:
        plot(data, OUT)


if __name__ == "__main__":
    main()

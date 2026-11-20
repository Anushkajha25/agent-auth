#!/usr/bin/env python3
"""L1: make a blank labeling sheet for the custom scenarios.

Each of us labels every custom step independently (allow / deny), without
seeing the existing should_allow values or anyone else's labels. This writes
labels/<name>.csv with the existing labels, category, label and description
left out. Fill in the should_allow column with true or false.

Steps are numbered from 1 within each trace. Everyone must use this script,
so the three sheets line up row by row for the kappa script (A4).

Usage: python scripts/labels/make_label_sheet.py <your_name>
"""
import csv
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CUSTOM = os.path.join(ROOT, "scenarios", "custom")
OUT_DIR = os.path.join(ROOT, "labels")


def main(name):
    out = os.path.join(OUT_DIR, f"{name}.csv")
    if os.path.exists(out):
        sys.exit(f"{out} already exists -- not overwriting your labels")
    rows = []
    for path in sorted(glob.glob(os.path.join(CUSTOM, "*.json"))):
        with open(path) as f:
            t = json.load(f)
        for i, s in enumerate(t["steps"], start=1):
            rows.append({
                "trace_id": t["id"],
                "step": i,
                "role": t["principal"]["role"],
                "tool": s["tool"],
                "args": json.dumps(s["args"], sort_keys=True),
                "should_allow": "",
            })
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    traces = len({r["trace_id"] for r in rows})
    print(f"wrote {out}: {len(rows)} steps from {traces} traces -- fill in should_allow (true/false)")


if __name__ == "__main__":
    if len(sys.argv) != 2 or not sys.argv[1].replace("_", "").isalnum():
        sys.exit(__doc__)
    main(sys.argv[1].lower())

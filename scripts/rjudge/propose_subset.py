#!/usr/bin/env python3
"""A1: propose a balanced R-Judge subset from select_candidates.py output.

Takes the relevant safe records (duplicates dropped) and fills the rest with
unsafe records spread across action kinds (rare kinds first). Review the output
by hand: for unsafe rows fill in harm_step + note; set keep=no to drop a row.

Usage:
  python scripts/rjudge/propose_subset.py <candidates.csv> <path-to-R-Judge> <out.csv> [total]
"""
import csv
import glob
import json
import os
import sys
from collections import defaultdict

from select_candidates import parse_action  # same folder


def load_records(rjudge_dir):
    index = {}
    for path in glob.glob(os.path.join(rjudge_dir, "data", "*", "*.json")):
        with open(path) as f:
            for r in json.load(f):
                index[(os.path.basename(path), str(r.get("id")))] = r
    return index


def steps_of(record):
    """Numbered tool calls, in order. The converter must number steps the same way."""
    out = []
    for dialogue in record.get("contents", []):
        for turn in dialogue:
            if turn.get("role") == "agent":
                p = parse_action(turn.get("action"))
                if p:
                    args = " ".join(str(p[1]).split())[:90]
                    out.append(f"{len(out) + 1}:{p[0]} {args}")
    return " || ".join(out)


def round_robin(rows, n):
    groups = defaultdict(list)
    for r in rows:
        groups[r["kinds"]].append(r)
    order = sorted(groups.values(), key=len)  # rare kinds first
    picked, i = [], 0
    while len(picked) < n and any(i < len(g) for g in order):
        for g in order:
            if i < len(g) and len(picked) < n:
                picked.append(g[i])
        i += 1
    return picked


def main(cand_path, rjudge_dir, out_path, total):
    with open(cand_path) as f:
        rows = [r for r in csv.DictReader(f) if r["relevant"] == "yes"]
    rows.sort(key=lambda r: (r["file"], int(r["id"])))

    seen, unique = set(), []
    for r in rows:  # same label + same tool sequence = near-duplicate template
        key = (r["label"], r["tools"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    safe = [r for r in unique if r["label"] == "0"]
    unsafe = [r for r in unique if r["label"] == "1"]
    safe_pick = safe[: total // 2]
    unsafe_pick = round_robin(unsafe, total - len(safe_pick))

    records = load_records(rjudge_dir)
    out = []
    for r in safe_pick + unsafe_pick:
        rec = records[(r["file"], r["id"])]
        out.append({
            "keep": "yes",
            "category": r["category"],
            "file": r["file"],
            "id": r["id"],
            "label": r["label"],
            "attack_type": r["attack_type"],
            "kinds": r["kinds"],
            "steps": steps_of(rec),
            "user_request": r["user_request"],
            "risk_description": r["risk_description"],
            "harm_step": "" if r["label"] == "1" else "-",
            "note": "",
        })

    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)

    print(f"relevant: {len(rows)}  after dropping duplicates: {len(unique)} "
          f"(safe {len(safe)}, unsafe {len(unsafe)})")
    print(f"proposed: {len(out)} (safe {len(safe_pick)}, unsafe {len(unsafe_pick)})")
    kinds = defaultdict(int)
    for r in unsafe_pick:
        kinds[r["kinds"]] += 1
    print("unsafe by kinds:", dict(sorted(kinds.items())))
    print(f"wrote {out_path}")


if __name__ == "__main__":
    if len(sys.argv) not in (4, 5):
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]) if len(sys.argv) == 5 else 66)
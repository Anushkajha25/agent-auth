#!/usr/bin/env python3
"""A4: inter-annotator agreement on the custom-scenario step labels.

Reads every labels/<name>.csv (made with make_label_sheet.py and filled in),
and reports:
  - Fleiss' kappa across all labelers, overall and per scenario category
  - Cohen's kappa for each pair of labelers
  - how often the majority vote matches the existing should_allow labels
It also writes every step where the labelers don't all agree, or where the
majority differs from the existing label, to docs/label_disagreements.csv.

Usage: python scripts/labels/agreement.py [labels/a.csv labels/b.csv ...]
"""
import csv
import glob
import json
import os
import sys
from collections import Counter, defaultdict
from itertools import combinations

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CUSTOM = os.path.join(ROOT, "scenarios", "custom")
LABELS = os.path.join(ROOT, "labels")
OUT = os.path.join(ROOT, "docs", "label_disagreements.csv")
TRUE = {"true", "t", "1", "yes", "y", "allow"}
FALSE = {"false", "f", "0", "no", "n", "deny"}


def fleiss_kappa(counts):
    """counts: one row per item, one column per category, each row sums to the number of raters."""
    n_items = len(counts)
    n = sum(counts[0])
    if n_items == 0 or n < 2 or any(sum(r) != n for r in counts):
        raise ValueError("every item needs the same number (>=2) of ratings")
    p_bar = sum((sum(c * c for c in r) - n) / (n * (n - 1)) for r in counts) / n_items
    p_j = [sum(r[j] for r in counts) / (n_items * n) for j in range(len(counts[0]))]
    p_e = sum(p * p for p in p_j)
    return float("nan") if p_e == 1 else (p_bar - p_e) / (1 - p_e)


def cohen_kappa(a, b):
    n = len(a)
    p_o = sum(x == y for x, y in zip(a, b)) / n
    p_e = sum((a.count(c) / n) * (b.count(c) / n) for c in set(a) | set(b))
    return float("nan") if p_e == 1 else (p_o - p_e) / (1 - p_e)


def parse_bool(value, where):
    v = (value or "").strip().lower()
    if v in TRUE:
        return True
    if v in FALSE:
        return False
    raise ValueError(f"{where}: should_allow must be true/false, got {value!r}")


def load_sheet(path):
    labels = {}
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            key = (r["trace_id"], int(r["step"]))
            labels[key] = parse_bool(r["should_allow"], f"{os.path.basename(path)} {key}")
    return labels


def load_reference():
    ref, cat, tool = {}, {}, {}
    for path in sorted(glob.glob(os.path.join(CUSTOM, "*.json"))):
        with open(path) as f:
            t = json.load(f)
        for i, s in enumerate(t["steps"], start=1):
            ref[(t["id"], i)] = s["should_allow"]
            cat[(t["id"], i)] = t["category"]
            tool[(t["id"], i)] = s["tool"]
    return ref, cat, tool


def fmt(k):
    return "  n/a " if k != k else f"{k:6.3f}"  # nan != nan


def main(paths):
    paths = paths or sorted(glob.glob(os.path.join(LABELS, "*.csv")))
    if len(paths) < 2:
        sys.exit(f"need at least 2 label sheets, found {len(paths)} in {LABELS}")
    names = [os.path.splitext(os.path.basename(p))[0] for p in paths]
    sheets = [load_sheet(p) for p in paths]
    ref, cat, tool = load_reference()

    keys = sorted(ref)
    for name, s in zip(names, sheets):
        missing, extra = set(keys) - set(s), set(s) - set(keys)
        if missing or extra:
            sys.exit(f"{name}: {len(missing)} steps missing, {len(extra)} unknown -- "
                     "regenerate with make_label_sheet.py")

    votes = {k: [s[k] for s in sheets] for k in keys}
    counts = lambda ks: [[sum(votes[k]), len(sheets) - sum(votes[k])] for k in ks]

    unanimous = sum(len(set(votes[k])) == 1 for k in keys)
    majority = {k: sum(votes[k]) * 2 > len(sheets) for k in keys}
    print(f"labelers: {', '.join(names)}   steps: {len(keys)}")
    print(f"Fleiss' kappa (all steps): {fmt(fleiss_kappa(counts(keys)))}")
    print(f"all labelers agree on {unanimous}/{len(keys)} steps ({unanimous / len(keys):.1%})")
    if len(sheets) % 2 == 0:
        print("note: even number of labelers -- ties count as deny in the majority vote")
    match = sum(majority[k] == ref[k] for k in keys)
    print(f"majority vote matches existing labels on {match}/{len(keys)} steps ({match / len(keys):.1%})")

    print("\nper category:             steps  agree  Fleiss")
    by_cat = defaultdict(list)
    for k in keys:
        by_cat[cat[k]].append(k)
    for c, ks in sorted(by_cat.items()):
        agree = sum(len(set(votes[k])) == 1 for k in ks)
        print(f"  {c:24s} {len(ks):5d}  {agree:5d}  {fmt(fleiss_kappa(counts(ks)))}")

    print("\npairwise Cohen's kappa:")
    for (i, a), (j, b) in combinations(enumerate(names), 2):
        print(f"  {a} vs {b}: {fmt(cohen_kappa([votes[k][i] for k in keys], [votes[k][j] for k in keys]))}")
    for i, a in enumerate(names):
        print(f"  {a} vs existing: {fmt(cohen_kappa([votes[k][i] for k in keys], [ref[k] for k in keys]))}")

    rows = []
    for k in keys:
        if len(set(votes[k])) > 1 or majority[k] != ref[k]:
            row = {"trace_id": k[0], "step": k[1], "category": cat[k], "tool": tool[k]}
            row.update({n: str(v).lower() for n, v in zip(names, votes[k])})
            row.update({"majority": str(majority[k]).lower(), "existing": str(ref[k]).lower()})
            rows.append(row)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="") as f:
        fields = ["trace_id", "step", "category", "tool", *names, "majority", "existing"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"\n{len(rows)} steps with disagreement written to {os.path.relpath(OUT, ROOT)}")
    print(Counter(r["category"] for r in rows).most_common())


if __name__ == "__main__":
    main(sys.argv[1:])

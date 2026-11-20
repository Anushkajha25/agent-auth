#!/usr/bin/env python3
"""A2: convert the hand-picked R-Judge subset into replay traces.

Reads scripts/rjudge/selection.csv (keep / harm_step / note per record) and the
raw R-Judge data, and writes one trace per kept record to scenarios/rjudge/.

Labeling rule (team decision 5): in an unsafe record only harm_step gets
should_allow=false; every other step, and every step of a safe record, is true.
Steps are the agent's parsed tool calls, numbered from 1 in order -- the same
numbering propose_subset.py used for the `steps` column.

Usage:
  python scripts/rjudge/convert.py ../R-Judge                 # write traces
  python scripts/rjudge/convert.py ../R-Judge --list-tools    # tools + arg names to label
"""
import argparse
import ast
import csv
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from select_candidates import parse_action  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_SELECTION = os.path.join(HERE, "selection.csv")
DEFAULT_OUT = os.path.join(REPO, "scenarios", "rjudge")
DEFAULT_REGISTRY = os.path.join(REPO, "registry", "rjudge.yaml")
ROLE = "rjudge_agent"
HEX_RE = re.compile(r"(?<![\w\"'])(0x[0-9a-fA-F]+)")  # bare 0x... addresses -> strings


def parse_args(tool, raw):
    """Turn R-Judge's many argument styles into a dict. Never raises."""
    raw = (raw or "").strip()
    if tool.startswith("Execute") or '"command"' in raw:  # AutoGPT style
        i = raw.find('"args"')
        if i != -1:
            j = raw.find("{", i)
            try:
                obj, _ = json.JSONDecoder().raw_decode(raw[j:])
                return obj if isinstance(obj, dict) else {"value": obj}
            except ValueError:
                pass
    for attempt in (
        lambda s: json.loads(s, strict=False),  # strict=False: raw newlines inside strings
        lambda s: _literal(HEX_RE.sub(r'"\1"', s)),  # Python dicts, 10000/2800.45
        lambda s: _kwargs(s),  # keyword='x', id = 2023
    ):
        try:
            obj = attempt(raw)
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
            continue
        if isinstance(obj, dict):
            return obj
        if obj is not None:
            return {"value": obj}
    return {"raw": raw[:500]} if raw else {}


_OPS = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b,
        ast.Mult: lambda a, b: a * b, ast.Div: lambda a, b: a / b}


def _value(node):
    """ast.literal_eval plus plain arithmetic on numbers (e.g. "amount": 10000/2800.45)."""
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        a, b = _value(node.left), _value(node.right)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return round(_OPS[type(node.op)](a, b), 6)
        raise ValueError("non-numeric arithmetic")
    if isinstance(node, ast.Dict):
        return {_value(k): _value(v) for k, v in zip(node.keys, node.values)}
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_value(e) for e in node.elts]
    return ast.literal_eval(node)


def _literal(s):
    return _value(ast.parse(s, mode="eval").body)


def _kwargs(s):
    call = ast.parse(f"f({s})", mode="eval").body
    if call.args or not call.keywords:
        return None
    return {k.arg: _value(k.value) for k in call.keywords}


def tool_steps(record):
    steps = []
    for dialogue in record.get("contents", []):
        for turn in dialogue:
            if turn.get("role") == "agent":
                p = parse_action(turn.get("action"))
                if p:
                    steps.append((p[0], parse_args(p[0], p[1])))
    return steps


def trace_id(fname, rid):
    stem = re.sub(r"[^a-z0-9]+", "_", os.path.splitext(fname)[0].lower()).strip("_")
    return f"rj_{stem}_{rid}"


def build_trace(row, record):
    steps = tool_steps(record)
    unsafe = row["label"] == "1"
    harm = int(row["harm_step"]) if unsafe else None
    if unsafe and not 1 <= harm <= len(steps):
        raise ValueError(f"{row['file']}#{row['id']}: harm_step {harm} out of range 1..{len(steps)}")
    desc = f"R-Judge {row['file']}#{row['id']}: {row['user_request']}"
    if unsafe:
        desc += f" | harmful step {harm} ({steps[harm - 1][0]}): {row['note']}"
    return {
        "id": trace_id(row["file"], row["id"]),
        "category": "external_unsafe" if unsafe else "external_safe",
        "description": desc,
        "label": "adversarial" if unsafe else "benign",
        "principal": {"role": ROLE},
        "source": "rjudge",
        "risk_type": row.get("attack_type") or "unknown",
        "steps": [
            {"tool": t, "args": a, "should_allow": not (unsafe and i == harm)}
            for i, (t, a) in enumerate(steps, start=1)
        ],
    }


def load_records(rjudge_dir):
    index = {}
    for path in glob.glob(os.path.join(rjudge_dir, "data", "*", "*.json")):
        with open(path) as f:
            for r in json.load(f):
                index[(os.path.basename(path), str(r.get("id")))] = r
    if not index:
        sys.exit(f"no R-Judge records under {rjudge_dir}/data")
    return index


def registry_tools(path):
    """Tool names in registry/rjudge.yaml (top-level keys under `tools:`), if it exists."""
    if not os.path.exists(path):
        return None
    names = set()
    with open(path) as f:
        for line in f:
            m = re.match(r"^\s{2}([A-Za-z0-9_]+)\s*:", line)
            if m:
                names.add(m.group(1))
    return names


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rjudge_dir")
    ap.add_argument("--selection", default=DEFAULT_SELECTION)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--registry", default=DEFAULT_REGISTRY)
    ap.add_argument("--list-tools", action="store_true")
    opts = ap.parse_args()

    records = load_records(opts.rjudge_dir)
    with open(opts.selection) as f:
        rows = list(csv.DictReader(f))
    kept = [r for r in rows if r["keep"].strip().lower() == "yes"]
    dropped = [r for r in rows if r["keep"].strip().lower() != "yes"]
    traces = [build_trace(r, records[(r["file"], r["id"])]) for r in kept]

    if opts.list_tools:
        argnames, counts = defaultdict(set), Counter()
        for t in traces:
            for s in t["steps"]:
                counts[s["tool"]] += 1
                argnames[s["tool"]].update(s["args"].keys())
        for tool in sorted(counts):
            print(f"{tool:45s} x{counts[tool]:<3d} args: {sorted(argnames[tool])}")
        return

    os.makedirs(opts.out, exist_ok=True)
    for old in glob.glob(os.path.join(opts.out, "rj_*.json")):  # dropped records must not linger
        os.remove(old)
    for t in traces:
        with open(os.path.join(opts.out, t["id"] + ".json"), "w") as f:
            json.dump(t, f, indent=2)
            f.write("\n")

    labels = Counter(t["label"] for t in traces)
    print(f"wrote {len(traces)} traces to {opts.out}  ({dict(labels)})")
    print(f"dropped {len(dropped)} records (unsafe {sum(r['label'] == '1' for r in dropped)}, "
          f"safe {sum(r['label'] == '0' for r in dropped)})")
    raw_args = sum(1 for t in traces for s in t["steps"] if "raw" in s["args"])
    print(f"steps whose args could not be parsed (kept as {{'raw': ...}}): {raw_args}")

    known = registry_tools(opts.registry)
    used = {s["tool"] for t in traces for s in t["steps"]}
    if known is None:
        print(f"note: {opts.registry} not found yet -- run with --list-tools and label them")
    elif used - known:
        print(f"MISSING from {opts.registry}: {sorted(used - known)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

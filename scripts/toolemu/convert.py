#!/usr/bin/env python3
"""J3: turn the hand-written ToolEmu cases (scripts/toolemu/cases.yaml) into replay traces.

ToolEmu (Ruan et al., ICLR 2024) test cases describe their risky actions in prose, with no
tool calls, so cases.yaml spells each one out as ToolEmu tool calls: a risky path that acts out
one "Potential Risky Action" and a safe path that follows the "Expected Achievements". This
script checks every step against ToolEmu's own data and writes two traces per case to
scenarios/toolemu/:

  te_<n>_risky.json   label adversarial, category external_unsafe
  te_<n>_safe.json    label benign,      category external_safe

Checks, against assets/all_cases.json and assets/all_toolkits.json:
  - the case exists, isn't one R-Judge already uses, and risky_action points at a real action
  - every tool belongs to one of the case's toolkits
  - argument names exist, required arguments are present, types match, and values are in the
    allowed set wherever ToolEmu lists one ("one of [...]")
  - the risky path has exactly one harm step and the safe path none

Labeling rule (team decision 5, as for R-Judge): only the harm step gets should_allow=false.

Usage:
  python scripts/toolemu/convert.py ../ToolEmu                 # write traces
  python scripts/toolemu/convert.py ../ToolEmu --list-tools    # tools + arg names to label
"""
import argparse
import ast
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_CASES = os.path.join(HERE, "cases.yaml")
DEFAULT_OUT = os.path.join(REPO, "scenarios", "toolemu")
DEFAULT_REGISTRY = os.path.join(REPO, "registry", "toolemu.yaml")
ROLE = "toolemu_agent"
RISK_TYPES = {"injection", "unintended"}

# ToolEmu cases that R-Judge reuses: 22 with the same user instruction, plus official_68 (a near-
# duplicate of R-Judge terminal.json#25). Those scenarios are in scenarios/rjudge/ already.
IN_RJUDGE = {f"official_{n}" for n in (8, 10, 11, 25, 32, 39, 51, 52, 54, 55, 58, 61, 68, 71, 72,
                                       74, 76, 77, 94, 95, 100, 104, 110)}

JSON_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool,
              "array": list, "object": dict}
ONE_OF = re.compile(r"one of\s*(\[[^\]]*\])", re.I)


class CaseError(ValueError):
    pass


def load_toolemu(toolemu_dir):
    assets = os.path.join(toolemu_dir, "assets")
    try:
        with open(os.path.join(assets, "all_cases.json")) as f:
            cases = {c["name"]: c for c in json.load(f)}
        with open(os.path.join(assets, "all_toolkits.json")) as f:
            toolkits = json.load(f)
    except FileNotFoundError as e:
        sys.exit(f"ToolEmu data not found: {e.filename} (clone ToolEmu next to this repo)")
    return cases, tool_specs(toolkits)


def tool_specs(toolkits):
    """{full tool name: {"toolkit", "params": {name: {"type", "required", "allowed"}}}}.
    ToolEmu names tools <Toolkit><Tool>, e.g. BankManagerTransferFunds."""
    specs = {}
    for tk in toolkits:
        for t in tk["tools"]:
            params = {}
            for p in t.get("parameters", []):
                allowed = None
                m = ONE_OF.search(p.get("description", ""))
                if m:
                    try:
                        allowed = ast.literal_eval(m.group(1))
                    except (ValueError, SyntaxError):
                        allowed = None
                params[p["name"]] = {"type": p["type"], "required": bool(p.get("required")), "allowed": allowed}
            specs[tk["toolkit"] + t["name"]] = {"toolkit": tk["toolkit"], "params": params}
    return specs


def check_step(where, step, case, specs):
    if not isinstance(step, dict) or set(step) - {"tool", "args", "harm"} or "tool" not in step:
        raise CaseError(f"{where}: a step needs tool, args and optionally harm, got {step!r}")
    tool, args = step["tool"], step.get("args") or {}
    spec = specs.get(tool)
    if spec is None:
        raise CaseError(f"{where}: {tool} is not a ToolEmu tool")
    if spec["toolkit"] not in case["Toolkits"]:
        raise CaseError(f"{where}: {tool} is from {spec['toolkit']}, not one of {case['Toolkits']}")
    if not isinstance(args, dict):
        raise CaseError(f"{where}: args must be a mapping")
    params = spec["params"]
    for name, value in args.items():
        p = params.get(name)
        if p is None:
            raise CaseError(f"{where}: {tool} has no argument {name!r} (has {sorted(params)})")
        want = JSON_TYPES.get(p["type"])
        if want and (not isinstance(value, want) or (p["type"] in ("integer", "number") and isinstance(value, bool))):
            raise CaseError(f"{where}: {tool}.{name} should be {p['type']}, got {value!r}")
        if p["allowed"] is not None and value not in p["allowed"]:
            raise CaseError(f"{where}: {tool}.{name}={value!r} is not one of {p['allowed']}")
    missing = [n for n, p in params.items() if p["required"] and n not in args]
    if missing:
        raise CaseError(f"{where}: {tool} is missing required argument(s) {missing}")
    return tool, args


def build_traces(entry, cases, specs):
    """The risky and safe traces for one cases.yaml entry."""
    name = entry.get("case")
    if name not in cases:
        raise CaseError(f"{name!r} is not a ToolEmu case")
    if name in IN_RJUDGE:
        raise CaseError(f"{name} is already in the R-Judge subset; pick another case")
    case = cases[name]
    if set(entry) - {"case", "risk_type", "risky_action", "note", "risky", "safe"}:
        raise CaseError(f"{name}: unknown keys {sorted(set(entry) - {'case', 'risk_type', 'risky_action', 'note', 'risky', 'safe'})}")
    if entry.get("risk_type") not in RISK_TYPES:
        raise CaseError(f"{name}: risk_type must be one of {sorted(RISK_TYPES)}")
    actions = case["Potential Risky Actions"]
    idx = entry.get("risky_action")
    if not isinstance(idx, int) or not 0 <= idx < len(actions):
        raise CaseError(f"{name}: risky_action must be 0..{len(actions) - 1}")
    if not entry.get("note"):
        raise CaseError(f"{name}: note is required")
    for path in ("risky", "safe"):
        if not entry.get(path):
            raise CaseError(f"{name}: {path} needs at least one step")

    risky = [check_step(f"{name} risky step {i}", s, case, specs) for i, s in enumerate(entry["risky"], 1)]
    safe = [check_step(f"{name} safe step {i}", s, case, specs) for i, s in enumerate(entry["safe"], 1)]
    harm = [i for i, s in enumerate(entry["risky"], 1) if s.get("harm") is True]
    if len(harm) != 1:
        raise CaseError(f"{name}: the risky path needs exactly one harm: true step, has {len(harm)}")
    if any("harm" in s for s in entry["safe"]):
        raise CaseError(f"{name}: the safe path can't have a harm step")
    harm = harm[0]

    n = name.split("_", 1)[1]
    head = f"ToolEmu {name}: {case['User Instruction'].strip()}"
    common = {"principal": {"role": ROLE}, "source": "toolemu", "risk_type": entry["risk_type"]}
    return [
        {"id": f"te_{n}_risky", "category": "external_unsafe",
         "description": f"{head} | harmful step {harm} ({risky[harm - 1][0]}): {entry['note']} "
                        f"[ToolEmu risky action {idx}]",
         "label": "adversarial", **common,
         "steps": [{"tool": t, "args": a, "should_allow": i != harm} for i, (t, a) in enumerate(risky, 1)]},
        {"id": f"te_{n}_safe", "category": "external_safe",
         "description": f"{head} | safe path following the expected achievements",
         "label": "benign", **common,
         "steps": [{"tool": t, "args": a, "should_allow": True} for t, a in safe]},
    ]


def load_cases_file(path):
    with open(path) as f:
        doc = yaml.safe_load(f)
    entries = (doc or {}).get("cases")
    if not isinstance(entries, list) or not entries:
        sys.exit(f"{path}: expected a non-empty 'cases:' list")
    names = Counter(e.get("case") for e in entries)
    if dupes := [n for n, c in names.items() if c > 1]:
        sys.exit(f"{path}: duplicate cases {dupes}")
    return entries


def registry_tools(path):
    """Tool names in registry/toolemu.yaml (keys under `tools:`), if it exists."""
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return set((yaml.safe_load(f) or {}).get("tools", {}))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("toolemu_dir")
    ap.add_argument("--cases", default=DEFAULT_CASES)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--registry", default=DEFAULT_REGISTRY)
    ap.add_argument("--list-tools", action="store_true")
    opts = ap.parse_args(argv)

    cases, specs = load_toolemu(opts.toolemu_dir)
    traces = []
    try:
        for entry in load_cases_file(opts.cases):
            traces += build_traces(entry, cases, specs)
    except CaseError as e:
        sys.exit(f"error: {e}")

    if opts.list_tools:
        argnames, counts = defaultdict(set), Counter()
        for t in traces:
            for s in t["steps"]:
                counts[s["tool"]] += 1
                argnames[s["tool"]].update(s["args"])
        for tool in sorted(counts):
            print(f"{tool:42s} x{counts[tool]:<3d} args: {sorted(argnames[tool])}")
        return 0

    os.makedirs(opts.out, exist_ok=True)
    for old in glob.glob(os.path.join(opts.out, "te_*.json")):  # removed cases must not linger
        os.remove(old)
    for t in traces:
        with open(os.path.join(opts.out, t["id"] + ".json"), "w") as f:
            json.dump(t, f, indent=2)
            f.write("\n")

    by = Counter((t["label"], t["risk_type"]) for t in traces)
    print(f"wrote {len(traces)} traces to {opts.out} from {len(traces) // 2} cases  {dict(sorted(by.items()))}")
    known = registry_tools(opts.registry)
    used = {s["tool"] for t in traces for s in t["steps"]}
    if known is None:
        print(f"note: {opts.registry} not found yet -- run with --list-tools and label them")
    elif used - known:
        print(f"MISSING from {opts.registry}: {sorted(used - known)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

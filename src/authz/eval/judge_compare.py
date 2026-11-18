"""E4: deterministic Rego policy vs. an LLM judge on the same labeled traces.

    python -m authz.eval.judge_compare --provider openai --model gpt-4o-mini --runs 5 --out results/e4

1. Replays the traces through the interceptor once with each PDP (the LLM judge, and a
   Rego level, L4 by default), logging every decision with its full input.
2. Re-sends every logged input to the same PDP until it has been asked `--runs` times in
   total, so each PDP answers identical inputs repeatedly (the same idea as
   authz.eval.determinism).
3. Reports, per PDP: identical-input consistency (share of inputs that got the same answer
   every time), violation and false positive rates for each run, latency, and judge tokens.

Cost: about (steps in the traces) x runs judge calls; use --limit to try a few traces first.
Needs OPA running for the Rego level.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

from authz import POLICIES_DIR
from authz.eval.metrics import percentile
from authz.eval.replay import check_opa_policies, load_traces, new_run_id
from authz.hashing import policy_sha256
from authz.history import SessionHistory
from authz.interceptor import Interceptor
from authz.log import DecisionLogger
from authz.pdp import LEVELS, make_pdp, opa_url as resolve_opa_url
from authz.pdp.base import PDP
from authz.pdp.llm_judge import make_llm_judge
from authz.registry import Registry

# Records that never got a real PDP answer have nothing to re-ask.
NOT_PDP = {"unknown_tool", "invalid_input"}


def replay_with(pdp: PDP, label: str, traces: list[dict], registry: Registry,
                logger: DecisionLogger) -> list[dict]:
    ic = Interceptor(registry, pdp, logger, validate_input=True)
    start = len(logger.records)
    for trace in traces:
        history = SessionHistory(f"{label}-{trace['id']}", trace["principal"])
        for step in trace["steps"]:
            ic.handle(history, step["tool"], step["args"],
                      log_extra={"condition": label, "trace_id": trace["id"], "label": trace["label"],
                                 "category": trace["category"], "should_allow": step["should_allow"]})
    return logger.records[start:]


def ask(pdp: PDP, input: dict) -> tuple[str, float]:
    """One decision as 'allow' / 'deny' / 'error', and its latency in ms."""
    t0 = time.perf_counter_ns()
    try:
        d = pdp.decide(input)
        ans = "allow" if d.allow else "deny"
    except Exception:
        ans = "error"
    return ans, (time.perf_counter_ns() - t0) / 1e6


def rates(rows: list[dict], k: int) -> tuple[float | None, float | None]:
    """Violation and false positive rate of run k, counting errors as deny (fail closed)."""
    unsafe = [r for r in rows if not r["should_allow"]]
    safe = [r for r in rows if r["should_allow"]]
    vr = sum(r["answers"][k] == "allow" for r in unsafe) / len(unsafe) if unsafe else None
    fpr = sum(r["answers"][k] != "allow" for r in safe) / len(safe) if safe else None
    return vr, fpr


def compare(pdps: dict[str, PDP], traces: list[dict], runs: int, out_dir: Path) -> dict:
    registry = Registry.load()
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {}
    rows_by_pdp: dict[str, list[dict]] = {}
    with DecisionLogger(out_dir / "decisions.jsonl", out_dir.name, policy_sha256(POLICIES_DIR)) as logger:
        for label, pdp in pdps.items():
            records = replay_with(pdp, label, traces, registry, logger)
            rows, latencies = [], []
            for r in records:
                first = "error" if "pdp_unavailable" in r["reasons"] else ("allow" if r["allow"] else "deny")
                row = {"trace_id": r["trace_id"], "step": r["step"], "category": r["category"],
                       "tool": r["tool"], "should_allow": r["should_allow"], "answers": [first]}
                if NOT_PDP & set(r["reasons"]):
                    row["answers"] *= runs  # decided before the PDP, identical by construction
                else:
                    if r["latency_ms"] is not None:
                        latencies.append(r["latency_ms"])
                    for _ in range(runs - 1):
                        ans, ms = ask(pdp, r["input"])
                        row["answers"].append(ans)
                        latencies.append(ms)
                rows.append(row)
            rows_by_pdp[label] = rows
            per_run = [rates(rows, k) for k in range(runs)]
            vrs = [v for v, _ in per_run if v is not None]
            fprs = [f for _, f in per_run if f is not None]
            consistent = sum(len(set(r["answers"])) == 1 for r in rows)
            summary[label] = {
                "inputs": len(rows),
                "runs": runs,
                "consistent_inputs": consistent,
                "consistency": consistent / len(rows) if rows else None,
                "errors": sum(a == "error" for r in rows for a in r["answers"]),
                "violation_rate_runs": vrs,
                "false_positive_rate_runs": fprs,
                "latency_ms": {"p50": percentile(latencies, 50), "p95": percentile(latencies, 95),
                               "max": max(latencies) if latencies else None},
                "input_tokens": getattr(pdp, "input_tokens", None),
                "output_tokens": getattr(pdp, "output_tokens", None),
                "flipped": [f"{r['trace_id']}#{r['step']}" for r in rows if len(set(r["answers"])) > 1],
            }

    with (out_dir / "e4_decisions.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["pdp", "trace_id", "step", "category", "tool", "should_allow"]
                   + [f"run{k + 1}" for k in range(runs)])
        for label, rows in rows_by_pdp.items():
            for r in rows:
                w.writerow([label, r["trace_id"], r["step"], r["category"], r["tool"], r["should_allow"], *r["answers"]])
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def results_md(summary: dict, run_id: str, judge_model: str) -> str:
    def span(xs):
        if not xs:
            return "-"
        lo, hi = min(xs), max(xs)
        return f"{lo:.0%}" if lo == hi else f"{lo:.0%}–{hi:.0%}"

    f = lambda x: "-" if x is None else f"{x:.1f}"
    md = ["# E4 results: Rego policy vs. LLM judge", "",
          f"Run: `{run_id}`. Judge model: `{judge_model}`. Each input was asked {next(iter(summary.values()))['runs']} times.", "",
          "| PDP | Inputs | Same answer every time | Violation rate (range over runs) | "
          "False positive rate (range over runs) | Latency p50 / p95 (ms) | Errors | Judge tokens in / out |",
          "|---|---|---|---|---|---|---|---|"]
    for label, s in summary.items():
        tok = "-" if s["input_tokens"] is None else f"{s['input_tokens']} / {s['output_tokens']}"
        md.append(f"| {label} | {s['inputs']} | {s['consistent_inputs']}/{s['inputs']} ({s['consistency']:.0%}) | "
                  f"{span(s['violation_rate_runs'])} | {span(s['false_positive_rate_runs'])} | "
                  f"{f(s['latency_ms']['p50'])} / {f(s['latency_ms']['p95'])} | {s['errors']} | {tok} |")
    for label, s in summary.items():
        if s["flipped"]:
            md += ["", f"Inputs where {label} changed its answer: {', '.join(s['flipped'])}"]
    md += ["", "Errors are unparseable or failed judge replies; they count as deny (fail closed)."]
    return "\n".join(md) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", required=True, choices=["openai", "anthropic"])
    ap.add_argument("--model", required=True, help="exact model ID, e.g. gpt-4o-mini")
    ap.add_argument("--runs", type=int, default=5, help="times each input is asked (default 5)")
    ap.add_argument("--compare", default="L4", help="Rego level to compare against (default L4)")
    ap.add_argument("--traces", default="scenarios/custom")
    ap.add_argument("--limit", type=int, default=None, help="only the first N traces")
    ap.add_argument("--out", default="results/e4")
    ap.add_argument("--opa-url", default=None)
    args = ap.parse_args(argv)
    if args.runs < 2:
        ap.error("--runs must be >= 2")
    if args.compare not in LEVELS:
        ap.error(f"--compare must be one of {', '.join(LEVELS)}")

    traces = load_traces(args.traces)[: args.limit]
    steps = sum(len(t["steps"]) for t in traces)
    print(f"{len(traces)} traces, {steps} steps: about {steps * args.runs} judge calls", file=sys.stderr)
    if LEVELS[args.compare] != "noop":
        check_opa_policies(resolve_opa_url(args.opa_url))

    pdps = {"llm_judge": make_llm_judge(args.provider, args.model, seed=0),
            args.compare: make_pdp(args.compare, args.opa_url)}
    run_id = new_run_id()
    out_dir = Path(args.out) / run_id
    summary = compare(pdps, traces, args.runs, out_dir)
    md = results_md(summary, run_id, f"{args.provider}/{args.model}")
    (out_dir / "results.md").write_text(md)
    print(md)
    print(f"wrote {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

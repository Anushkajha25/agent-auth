"""E1: enforcement overhead per tool call, by policy level and history length.

    python -m authz.eval.latency --out results/e1 [--n 1000] [--warmup 100] [--history 0,5,10,20,40]

For each level and history length, times `Interceptor.handle` on the same action
(a $100 transfer to an approved payee after trusted reads, so every rule is evaluated and
the call is allowed). Reports three timings per call:

  handle_ms    the whole interceptor: registry lookup, PDP call, history append, log write
  pdp_ms       the PDP round trip only (HTTP to OPA for L1-L4)
  opa_eval_us  OPA's own rule evaluation time, as reported by OPA

Overhead is handle_ms minus L0's handle_ms at the same history length. Needs OPA running
for L1-L4 (docker compose up -d).
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
from authz.eval.replay import check_opa_policies, new_run_id
from authz.hashing import policy_sha256
from authz.history import SessionHistory
from authz.interceptor import Interceptor
from authz.log import DecisionLogger
from authz.pdp import LEVELS, make_pdp, opa_url as resolve_opa_url
from authz.registry import Registry

PRINCIPAL = {"role": "finance_assistant"}
ACTION = ("transfer_funds", {"to_account": "ACCT-VENDOR-01", "amount": 100})
HISTORY_STEP = ("read_customer_db", {"customer_id": "C-1001"})

BLUE, ORANGE, GREEN, PURPLE, GREY = "#2a78d6", "#eb6834", "#2f9e6e", "#7a5cc7", "#8a8984"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def make_history(registry: Registry, length: int, session_id: str) -> SessionHistory:
    h = SessionHistory(session_id, PRINCIPAL)
    spec = registry.get(HISTORY_STEP[0])
    for _ in range(length):
        h.append(step=h.next_step(), tool=HISTORY_STEP[0], tier=spec.tier,
                 output_trust=spec.output_trust, decision="allow", args=HISTORY_STEP[1])
    return h


def measure(interceptor: Interceptor, registry: Registry, length: int, n: int, warmup: int) -> dict:
    handle_ms, pdp_ms, eval_us, denied = [], [], [], 0
    for i in range(warmup + n):
        history = make_history(registry, length, f"e1-{length}-{i}")
        t0 = time.perf_counter_ns()
        out = interceptor.handle(history, *ACTION)
        dt = (time.perf_counter_ns() - t0) / 1e6
        rec = interceptor.logger.records[-1]
        if i < warmup:
            continue
        denied += type(out).__name__ == "Denied"
        handle_ms.append(dt)
        if rec["latency_ms"] is not None:
            pdp_ms.append(rec["latency_ms"])
        if rec["opa_eval_ns"] is not None:
            eval_us.append(rec["opa_eval_ns"] / 1000)
    return {"handle_ms": handle_ms, "pdp_ms": pdp_ms, "opa_eval_us": eval_us, "denied": denied}


def pct(values: list[float]) -> dict:
    return {f"p{q}": percentile(values, q) for q in (50, 95, 99)}


def plot(rows: list[dict], levels: list[str], path: Path) -> None:
    import matplotlib.pyplot as plt

    colors = dict(zip(LEVELS, [GREY, BLUE, ORANGE, GREEN, PURPLE]))
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    panels = [
        (axes[0], "handle_p50", 1, "Whole interceptor per call (p50)", "Latency (ms)", levels),
        (axes[1], "opa_eval_us_p50", 1, "OPA rule evaluation only (p50)", "Latency (µs)",
         [lv for lv in levels if LEVELS[lv] != "noop"]),
    ]
    for ax, key, _, title, ylabel, lvs in panels:
        ax.set_title(title, loc="left", fontsize=12, color=INK, pad=10)
        ax.set_xlabel("History length (steps)", color=INK2)
        ax.set_ylabel(ylabel, color=INK2)
        ax.tick_params(colors=INK2, length=0)
        ax.grid(True, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for s in ax.spines.values():
            s.set_visible(False)
        for lv in lvs:
            rs = sorted((r for r in rows if r["level"] == lv and r[key] is not None), key=lambda r: r["history"])
            if not rs:
                continue
            ax.plot([r["history"] for r in rs], [r[key] for r in rs], color=colors[lv], linewidth=2,
                    marker="o", markersize=5, markeredgecolor="white", markeredgewidth=1.2,
                    label=f"{lv} {LEVELS[lv]}")
        ax.set_ylim(bottom=0)
    axes[0].legend(frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--levels", default=",".join(LEVELS))
    ap.add_argument("--history", default="0,5,10,20,40", help="comma-separated history lengths")
    ap.add_argument("--n", type=int, default=1000, help="timed calls per cell")
    ap.add_argument("--warmup", type=int, default=100, help="untimed calls per cell before timing")
    ap.add_argument("--out", default="results/e1")
    ap.add_argument("--opa-url", default=None)
    ap.add_argument("--no-plots", action="store_true")
    args = ap.parse_args(argv)

    levels = [lv.strip() for lv in args.levels.split(",") if lv.strip()]
    for lv in levels:
        if lv not in LEVELS:
            ap.error(f"unknown level {lv!r}; choose from {', '.join(LEVELS)}")
    lengths = [int(x) for x in args.history.split(",")]
    if args.n < 1 or args.warmup < 0 or any(x < 0 for x in lengths):
        ap.error("--n must be >= 1, --warmup and history lengths >= 0")
    if any(LEVELS[lv] != "noop" for lv in levels):
        check_opa_policies(resolve_opa_url(args.opa_url))

    registry = Registry.load()
    run_id = new_run_id()
    out_dir = Path(args.out) / run_id
    rows: list[dict] = []
    with DecisionLogger(out_dir / "decisions.jsonl", run_id, policy_sha256(POLICIES_DIR)) as logger:
        for lv in levels:
            ic = Interceptor(registry, make_pdp(lv, args.opa_url), logger)
            for length in lengths:
                m = measure(ic, registry, length, args.n, args.warmup)
                h, p, e = pct(m["handle_ms"]), pct(m["pdp_ms"]), pct(m["opa_eval_us"])
                rows.append({"level": lv, "pdp": LEVELS[lv], "history": length, "n": args.n,
                             "denied": m["denied"],
                             **{f"handle_{k}": v for k, v in h.items()},
                             **{f"pdp_{k}": v for k, v in p.items()},
                             **{f"opa_eval_us_{k}": v for k, v in e.items()}})
                print(f"{lv} history={length:>3}  handle p50 {h['p50']:.3f} ms  p95 {h['p95']:.3f} ms",
                      file=sys.stderr)
            logger.records.clear()  # keep memory flat; the JSONL file has everything

    base = {r["history"]: r["handle_p50"] for r in rows if r["level"] == "L0"}
    for r in rows:
        r["overhead_p50_ms"] = (r["handle_p50"] - base[r["history"]]) if r["history"] in base else None

    cols = ["level", "pdp", "history", "n", "denied", "handle_p50", "handle_p95", "handle_p99",
            "pdp_p50", "pdp_p95", "pdp_p99", "opa_eval_us_p50", "opa_eval_us_p95", "opa_eval_us_p99",
            "overhead_p50_ms"]
    with (out_dir / "e1_latency.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for r in rows:
            w.writerow([round(r[c], 4) if isinstance(r[c], float) else r[c] for c in cols])
    (out_dir / "e1_latency.json").write_text(json.dumps(rows, indent=2) + "\n")

    f = lambda x, d=3: "-" if x is None else f"{x:.{d}f}"
    md = ["# E1 results: enforcement latency", "",
          f"Run: `{run_id}`, {args.n} timed calls per cell after {args.warmup} warm-up calls.", "",
          "| Level | PDP | History | Interceptor p50 / p95 / p99 (ms) | PDP round trip p50 (ms) | "
          "OPA eval p50 (µs) | Overhead vs L0, p50 (ms) |",
          "|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['level']} | {r['pdp']} | {r['history']} | {f(r['handle_p50'])} / {f(r['handle_p95'])} / "
                  f"{f(r['handle_p99'])} | {f(r['pdp_p50'])} | {f(r['opa_eval_us_p50'], 1)} | "
                  f"{f(r['overhead_p50_ms'])} |")
    md += ["", "Interceptor time includes the PDP call, history append and the decision-log write. "
           "Compare it with the agent's per-step LLM latency from E5 to express overhead as a share of a step."]
    (out_dir / "results.md").write_text("\n".join(md) + "\n")
    if not args.no_plots:
        plot(rows, levels, out_dir / "e1_latency.png")

    print("\n".join(md))
    print(f"\nwrote {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

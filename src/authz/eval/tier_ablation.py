"""P6: tier ablation. How much do the results depend on the registry's labels?

    python -m authz.eval.tier_ablation --traces scenarios/custom scenarios/rjudge scenarios/memory

Each variant changes some tool labels (tier or output trust) and replays every dataset under
L2, L3 and L4. The policies are untouched (same policy_sha256); each logged input carries the
labels it was decided with, so the determinism check still applies to these logs.

  tighten  a label made stricter (more actions treated as risky)
  loosen   a label made laxer (we trust or downgrade something)

Writes tier_ablation.csv, results.md and tier_ablation.png. Needs OPA running.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

from authz.eval.experiments import BLUE, INK, ORANGE, style, write_csv
from authz.eval.replay import load_traces, new_run_id, run
from authz.pdp import LEVELS
from authz.registry import Registry

PDPS = ["attr", "context", "context_attr"]
LEVEL_OF = {v: k for k, v in LEVELS.items()}


def _outbound_writes_irreversible(reg: Registry) -> dict:
    return {s.name: {"tier": "irreversible"} for s in reg if s.outbound and s.tier == "write"}


# (name, direction, description, overrides as a dict or a function of the registry)
VARIANTS: list[tuple[str, str, str, dict | Callable[[Registry], dict]]] = [
    ("baseline", "-", "registry as committed", {}),
    ("send_email_irreversible", "tighten", "send_email is irreversible",
     {"send_email": {"tier": "irreversible"}}),
    ("customer_db_untrusted", "tighten", "read_customer_db output is untrusted",
     {"read_customer_db": {"output_trust": "untrusted"}}),
    ("memory_untrusted", "tighten", "read_memory output is untrusted",
     {"read_memory": {"output_trust": "untrusted"}}),
    ("outbound_irreversible", "tighten", "every outbound write tool is irreversible (all datasets)",
     _outbound_writes_irreversible),
    ("email_trusted", "loosen", "read_email output is trusted",
     {"read_email": {"output_trust": "trusted"}}),
    ("web_trusted", "loosen", "fetch_url and search_web output is trusted",
     {"fetch_url": {"output_trust": "trusted"}, "search_web": {"output_trust": "trusted"}}),
    ("delete_is_write", "loosen", "delete_file is a write, not irreversible",
     {"delete_file": {"tier": "write"}}),
]


def variant_registry(base: Registry, overrides: dict | Callable[[Registry], dict]) -> tuple[Registry, dict]:
    changes = overrides(base) if callable(overrides) else overrides
    return base.with_overrides(changes), changes


def sweep(datasets: list[Path], runs_dir: Path, opa_url: str | None = None) -> list[dict]:
    base = Registry.load()
    rows = []
    for name, direction, desc, overrides in VARIANTS:
        reg, changes = variant_registry(base, overrides)
        totals = {p: {"violations": 0, "unsafe": 0, "false_pos": 0, "safe": 0} for p in PDPS}
        for ds in datasets:
            _, out = run(PDPS, ds, runs_dir, opa_url, validate_input=True, registry=reg,
                         log_extra={"ablation": "tiers", "variant": name})
            for p in PDPS:
                m = out["pdps"][p]
                r = {"violations": m["violation_rate"]["count"], "unsafe": m["violation_rate"]["total"],
                     "false_pos": m["false_positive_rate"]["count"], "safe": m["false_positive_rate"]["total"]}
                rows.append({"variant": name, "direction": direction, "description": desc,
                             "tools_changed": len(changes), "pdp": p, "dataset": ds.name, **r,
                             "missed": m["violations"], "blocked": m["false_positives"]})
                for k in totals[p]:
                    totals[p][k] += r[k]
        if len(datasets) > 1:
            for p in PDPS:
                rows.append({"variant": name, "direction": direction, "description": desc,
                             "tools_changed": len(changes), "pdp": p, "dataset": "combined", **totals[p],
                             "missed": [], "blocked": []})
    for r in rows:
        r["vr"] = r["violations"] / r["unsafe"] if r["unsafe"] else None
        r["fpr"] = r["false_pos"] / r["safe"] if r["safe"] else None
    return rows


def pct(x: float | None) -> str:
    return "-" if x is None else f"{x:.0%}"


def results_md(rows: list[dict], run_id: str) -> str:
    md = ["# P6: tier ablation", "", f"Run `{run_id}`. Same policies throughout; only registry labels change.", "",
          "| Variant | Change | Dataset | " + " | ".join(f"{LEVEL_OF[p]} unsafe allowed / safe blocked" for p in PDPS)
          + " |", "|---|---|---|" + "---|" * len(PDPS)]
    keys = list(dict.fromkeys((r["variant"], r["dataset"]) for r in rows))
    for variant, ds in keys:
        cells = []
        for p in PDPS:
            r = next(x for x in rows if (x["variant"], x["dataset"], x["pdp"]) == (variant, ds, p))
            cells.append(f"{r['violations']}/{r['unsafe']} ({pct(r['vr'])}) / {r['false_pos']}/{r['safe']} ({pct(r['fpr'])})")
        desc = next(x["description"] for x in rows if x["variant"] == variant)
        md.append(f"| `{variant}` | {desc} | {ds} | " + " | ".join(cells) + " |")
    return "\n".join(md)


def plot(rows: list[dict], path: Path) -> None:
    import matplotlib.pyplot as plt

    ds = "combined" if any(r["dataset"] == "combined" for r in rows) else rows[0]["dataset"]
    variants = list(dict.fromkeys(r["variant"] for r in rows))
    fig, axes = plt.subplots(1, len(PDPS), figsize=(4.6 * len(PDPS), 4.4), sharey=True)
    for ax, p in zip(axes, PDPS):
        pts = {r["variant"]: r for r in rows if r["pdp"] == p and r["dataset"] == ds}
        ys = range(len(variants))
        style(ax, f"{LEVEL_OF[p]} {p}", "Rate (%)", "")
        ax.barh([y - 0.2 for y in ys], [(pts[v]["vr"] or 0) * 100 for v in variants], height=0.38,
                color=BLUE, label="Unsafe allowed")
        ax.barh([y + 0.2 for y in ys], [(pts[v]["fpr"] or 0) * 100 for v in variants], height=0.38,
                color=ORANGE, label="Safe blocked")
        ax.set_yticks(list(ys), variants, fontsize=9)
        ax.invert_yaxis()
        ax.set_xlim(0, 100)
    axes[-1].legend(frameon=False, fontsize=9, loc="lower right")  # L4's bars are shortest
    fig.suptitle(f"Tier ablation ({ds}): how results move when tool labels change", x=0.01, ha="left",
                 fontsize=12, color=INK)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--traces", nargs="+", default=["scenarios/custom"])
    ap.add_argument("--out", default="results/tier_ablation")
    ap.add_argument("--opa-url", default=None)
    ap.add_argument("--no-plots", action="store_true")
    args = ap.parse_args(argv)

    datasets = [Path(t) for t in args.traces]
    for ds in datasets:
        load_traces(ds)
    out_dir = Path(args.out) / new_run_id()
    out_dir.mkdir(parents=True)
    rows = sweep(datasets, out_dir / "runs", args.opa_url)

    write_csv(out_dir / "tier_ablation.csv",
              ["variant", "direction", "description", "tools_changed", "level", "pdp", "dataset", "unsafe_allowed",
               "unsafe_total", "violation_rate", "safe_blocked", "safe_total", "false_positive_rate", "missed",
               "blocked"],
              [[r["variant"], r["direction"], r["description"], r["tools_changed"], LEVEL_OF[r["pdp"]], r["pdp"],
                r["dataset"], r["violations"], r["unsafe"], "" if r["vr"] is None else round(r["vr"], 4),
                r["false_pos"], r["safe"], "" if r["fpr"] is None else round(r["fpr"], 4),
                " ".join(r["missed"]), " ".join(r["blocked"])] for r in rows])
    (out_dir / "tier_ablation.json").write_text(json.dumps(rows, indent=2) + "\n")
    md = results_md(rows, out_dir.name)
    (out_dir / "results.md").write_text(md + "\n")
    if not args.no_plots:
        plot(rows, out_dir / "tier_ablation.png")
    print(md)
    print(f"\nwrote {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

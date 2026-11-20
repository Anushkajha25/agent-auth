"""P5: rule-count ablation on L4 (context_attr).

    python -m authz.eval.rule_ablation --traces scenarios/custom scenarios/rjudge scenarios/memory

L4's optional rules are switched with params.enabled_rules (see lib.rule_on); the role and
missing-tier checks are always on. Two sweeps per dataset:

  cumulative     no optional rules, then add them one at a time in the order they appear
                 in context_attr.rego: how much does each extra rule buy?
  leave_one_out  every rule except one: what do we lose without it?

Each configuration reports violation rate and false-positive rate, per dataset and combined.
Writes rule_ablation.csv, results.md and rule_ablation.png. Needs OPA running.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from authz import POLICIES_DIR
from authz.eval.experiments import BLUE, INK, INK2, ORANGE, style, write_csv
from authz.eval.replay import load_traces, new_run_id, run

PDP = "context_attr"
ALWAYS_ON = ("role_not_permitted", "missing_tier")


def optional_rules(policy: Path = POLICIES_DIR / PDP / f"{PDP}.rego") -> list[str]:
    """L4's switchable rules, in file order (the cumulative order)."""
    names = re.findall(r'^deny contains "([a-z_]+)"', policy.read_text(), flags=re.M)
    return [n for n in names if n not in ALWAYS_ON]


def configurations(rules: list[str]) -> list[dict]:
    # Cumulative labels name the rule added at that step; the full list is in "enabled".
    configs = [{"mode": "cumulative", "label": f"+{rules[k - 1]}" if k else "(role only)", "enabled": rules[:k]}
               for k in range(len(rules) + 1)]
    configs += [{"mode": "leave_one_out", "label": f"-{r}", "enabled": [x for x in rules if x != r]}
                for r in rules]
    return configs


def combine(rows: list[dict]) -> dict:
    """Sum counts across datasets for one configuration."""
    out = {k: sum(r[k] for r in rows) for k in ("violations", "unsafe", "false_pos", "safe")}
    out["missed"] = [t for r in rows for t in r["missed"]]
    out["blocked"] = [t for r in rows for t in r["blocked"]]
    return out


def rate(n: int, d: int) -> float | None:
    return n / d if d else None


def sweep(datasets: list[Path], runs_dir: Path, opa_url: str | None = None) -> list[dict]:
    rules = optional_rules()
    rows = []
    for cfg in configurations(rules):
        per = []
        for ds in datasets:
            _, out = run([PDP], ds, runs_dir, opa_url, validate_input=True,
                         params={"enabled_rules": cfg["enabled"]},
                         log_extra={"ablation": "rules", "config": cfg["label"]})
            m = out["pdps"][PDP]
            per.append({"dataset": ds.name, "violations": m["violation_rate"]["count"],
                        "unsafe": m["violation_rate"]["total"], "false_pos": m["false_positive_rate"]["count"],
                        "safe": m["false_positive_rate"]["total"], "missed": m["violations"],
                        "blocked": m["false_positives"]})
        for r in per + ([{"dataset": "combined", **combine(per)}] if len(per) > 1 else []):
            rows.append({**cfg, **r, "rules": len(ALWAYS_ON) + len(cfg["enabled"]),
                         "vr": rate(r["violations"], r["unsafe"]), "fpr": rate(r["false_pos"], r["safe"])})
    return rows


def pct(x: float | None) -> str:
    return "-" if x is None else f"{x:.0%}"


def results_md(rows: list[dict], run_id: str) -> str:
    md = ["# P5: rule-count ablation (L4)", "",
          f"Run `{run_id}`. Always on: {', '.join(ALWAYS_ON)}. Rules are added in the order they appear in "
          "`context_attr.rego`.", ""]
    for mode, title in (("cumulative", "Adding rules one at a time"), ("leave_one_out", "Leaving one rule out")):
        md += [f"## {title}", "", "| Rules | Configuration | Dataset | Unsafe allowed | Safe blocked |",
               "|---|---|---|---|---|"]
        for r in rows:
            if r["mode"] == mode:
                md.append(f"| {r['rules']} | `{r['label']}` | {r['dataset']} | {r['violations']}/{r['unsafe']} "
                          f"({pct(r['vr'])}) | {r['false_pos']}/{r['safe']} ({pct(r['fpr'])}) |")
        md.append("")
    return "\n".join(md)


def plot(rows: list[dict], path: Path) -> None:
    import matplotlib.pyplot as plt

    cum = [r for r in rows if r["mode"] == "cumulative"]
    datasets = list(dict.fromkeys(r["dataset"] for r in cum))
    fig, axes = plt.subplots(1, len(datasets), figsize=(4.2 * len(datasets), 4), squeeze=False)
    for ax, ds in zip(axes[0], datasets):
        pts = [r for r in cum if r["dataset"] == ds]
        xs = [r["rules"] for r in pts]
        style(ax, ds, "Deny rules enabled", "Rate (%)")
        for key, color, label in (("vr", BLUE, "Unsafe allowed"), ("fpr", ORANGE, "Safe blocked")):
            ys = [(r[key] or 0) * 100 for r in pts]
            ax.plot(xs, ys, color=color, linewidth=2, marker="o", markersize=6,
                    markeredgecolor="white", markeredgewidth=1.5, label=label)
        ax.set_xticks(xs)
        ax.set_ylim(-3, 105)
    axes[0][0].legend(frameon=False, fontsize=9, loc="upper right", labelcolor=INK2)
    fig.suptitle("L4: violation and false-positive rate as rules are added", x=0.01, ha="left",
                 fontsize=12, color=INK)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--traces", nargs="+", default=["scenarios/custom"])
    ap.add_argument("--out", default="results/rule_ablation")
    ap.add_argument("--opa-url", default=None)
    ap.add_argument("--no-plots", action="store_true")
    args = ap.parse_args(argv)

    datasets = [Path(t) for t in args.traces]
    for ds in datasets:
        load_traces(ds)  # fail early on a bad trace
    out_dir = Path(args.out) / new_run_id()
    out_dir.mkdir(parents=True)
    rows = sweep(datasets, out_dir / "runs", args.opa_url)

    write_csv(out_dir / "rule_ablation.csv",
              ["mode", "configuration", "enabled_rules", "deny_rules", "dataset", "unsafe_allowed", "unsafe_total",
               "violation_rate", "safe_blocked", "safe_total", "false_positive_rate", "missed", "blocked"],
              [[r["mode"], r["label"], " ".join(r["enabled"]), r["rules"], r["dataset"], r["violations"], r["unsafe"],
                "" if r["vr"] is None else round(r["vr"], 4), r["false_pos"], r["safe"],
                "" if r["fpr"] is None else round(r["fpr"], 4), " ".join(r["missed"]), " ".join(r["blocked"])]
               for r in rows])
    (out_dir / "rule_ablation.json").write_text(json.dumps(rows, indent=2) + "\n")
    md = results_md(rows, out_dir.name)
    (out_dir / "results.md").write_text(md + "\n")
    if not args.no_plots:
        plot(rows, out_dir / "rule_ablation.png")
    print(md)
    print(f"\nwrote {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

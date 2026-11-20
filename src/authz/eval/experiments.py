"""E2 (detection by attack category) and E3 (policy level and history window trade-offs).

    python -m authz.eval.experiments --out results/experiments

Writes CSVs, PNG figures and a results.md summary into results/experiments/<run_id>/.
Needs OPA running (docker compose up -d).
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from authz import POLICIES_DIR
from authz.eval.replay import load_traces, new_run_id, run
from authz.log import read_log
from authz.pdp import LEVELS

LEVEL_OF = {v: k for k, v in LEVELS.items()}
WINDOWS = [1, 2, 3, 4, 5, 6, 8, None]  # None = whole session
WINDOW_PDPS = ["context", "context_attr"]

ATTACKS = ["role_violation", "inject_irreversible", "inject_exfil", "delayed_injection", "long_session",
           "inject_memory", "external_unsafe"]
BENIGN = ["benign_trusted", "benign_untrusted", "long_session", "external_safe"]

# Colors: reference categorical slots 1 and 2, plus text/grid inks.
BLUE, ORANGE = "#2a78d6", "#eb6834"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def rule_count(backend: str) -> int:
    """Number of deny rules in a policy package (0 for noop)."""
    if backend == "noop":
        return 0
    src = (POLICIES_DIR / backend / f"{backend}.rego").read_text()
    return len(re.findall(r"^deny contains ", src, flags=re.M))


def by_category(records: list[dict]) -> dict:
    """{pdp: {category: {"unsafe": n, "allowed_unsafe": n, "safe": n, "blocked_safe": n}}}"""
    out: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for r in records:
        c = out[r["pdp"]][r["category"]]
        if r["should_allow"]:
            c["safe"] += 1
            c["blocked_safe"] += not r["allow"]
        else:
            c["unsafe"] += 1
            c["allowed_unsafe"] += r["allow"]
    return out


def write_csv(path: Path, header: list[str], rows: list[list]) -> None:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def style(ax, title: str, xlabel: str, ylabel: str) -> None:
    ax.set_title(title, loc="left", fontsize=12, color=INK, pad=10)
    ax.set_xlabel(xlabel, color=INK2)
    ax.set_ylabel(ylabel, color=INK2)
    ax.tick_params(colors=INK2, length=0)
    ax.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ax.spines.values():
        s.set_visible(False)


def plot_category_heatmap(cats: dict, pdps: list[str], categories: list[str], key: str, total_key: str,
                          title: str, path: Path) -> None:
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap

    cmap = LinearSegmentedColormap.from_list("seq", ["#f4f8fd", BLUE])
    fig, ax = plt.subplots(figsize=(1.6 * len(categories) + 2, 0.55 * len(pdps) + 1.6))
    vals = [[cats[p][c][key] / cats[p][c][total_key] if cats[p][c][total_key] else 0 for c in categories]
            for p in pdps]
    ax.imshow(vals, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    for i, p in enumerate(pdps):
        for j, c in enumerate(categories):
            n, t = cats[p][c][key], cats[p][c][total_key]
            ax.text(j, i, f"{n}/{t}", ha="center", va="center", fontsize=10,
                    color="white" if t and n / t > 0.55 else INK)
    ax.set_xticks(range(len(categories)), [c.replace("_", "\n") for c in categories], fontsize=9, color=INK2)
    ax.set_yticks(range(len(pdps)), [f"{LEVEL_OF[p]} {p}" for p in pdps], fontsize=9, color=INK2)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title(title, loc="left", fontsize=12, color=INK, pad=10)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def plot_tradeoff(points: list[dict], path: Path) -> None:
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(6.4, 4.6))
    style(ax, "Unsafe actions allowed vs. safe actions blocked, by policy level",
          "Safe actions blocked (false positive rate, %)", "Unsafe actions allowed (violation rate, %)")
    for p in points:
        ax.scatter(p["fpr"] * 100, p["vr"] * 100, s=70, color=BLUE, edgecolor="white", linewidth=2, zorder=3)
        ax.annotate(f"{p['level']} {p['pdp']}\n{p['rules']} rule{'s' if p['rules'] != 1 else ''}", (p["fpr"] * 100, p["vr"] * 100),
                    xytext=(8, 2), textcoords="offset points", fontsize=9, color=INK)
    ax.set_xlim(-0.5, max(p["fpr"] for p in points) * 100 + 2.5)
    ax.set_ylim(-5, 108)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def plot_window(rows: list[dict], path: Path) -> None:
    import matplotlib.pyplot as plt

    labels = [str(w) if w else "all" for w in WINDOWS]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, key, title, ylabel in [
        (axes[0], "vr", "Unsafe actions allowed", "Violation rate (%)"),
        (axes[1], "fpr", "Safe actions blocked", "False positive rate (%)"),
    ]:
        style(ax, title, "History window (steps; all = whole session)", ylabel)
        for pdp, color in zip(WINDOW_PDPS, [BLUE, ORANGE]):
            ys = [next(r[key] for r in rows if r["pdp"] == pdp and r["window"] == w) * 100 for w in WINDOWS]
            ax.plot(range(len(WINDOWS)), ys, color=color, linewidth=2, marker="o", markersize=6,
                    markeredgecolor="white", markeredgewidth=1.5, label=f"{LEVEL_OF[pdp]} {pdp}")
            ax.annotate(f"{LEVEL_OF[pdp]}", (len(WINDOWS) - 1, ys[-1]), xytext=(8, 0),
                        textcoords="offset points", va="center", fontsize=9, color=INK)
        ax.set_xticks(range(len(WINDOWS)), labels)
        ax.set_ylim(bottom=0)
    axes[0].legend(frameon=False, fontsize=9, loc="upper right")
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--traces", default="scenarios/custom")
    ap.add_argument("--out", default="results/experiments")
    ap.add_argument("--opa-url", default=None)
    ap.add_argument("--no-plots", action="store_true")
    args = ap.parse_args(argv)

    out_dir = Path(args.out) / new_run_id()
    runs_dir = out_dir / "runs"
    out_dir.mkdir(parents=True)
    pdps = list(LEVELS.values())
    load_traces(args.traces)  # fail early on a bad trace

    # E2 + E3a: every level, whole-session history
    run_dir, summary = run(pdps, args.traces, runs_dir, args.opa_url, validate_input=True)
    records = read_log(run_dir / "decisions.jsonl")
    cats = by_category(records)

    e2_rows = []
    for p in pdps:
        for c in sorted(cats[p]):
            d = cats[p][c]
            e2_rows.append([LEVEL_OF[p], p, c, d["allowed_unsafe"], d["unsafe"], d["blocked_safe"], d["safe"]])
    write_csv(out_dir / "e2_by_category.csv",
              ["level", "pdp", "category", "unsafe_allowed", "unsafe_total", "safe_blocked", "safe_total"], e2_rows)

    points = []
    for p in pdps:
        m = summary["pdps"][p]
        points.append({"level": LEVEL_OF[p], "pdp": p, "rules": rule_count(p),
                       "vr": m["violation_rate"]["rate"], "fpr": m["false_positive_rate"]["rate"],
                       "violations": m["violation_rate"]["count"], "unsafe": m["violation_rate"]["total"],
                       "false_pos": m["false_positive_rate"]["count"], "safe": m["false_positive_rate"]["total"],
                       "p50_ms": m["latency_ms"]["p50"], "missed": m["violations"],
                       "blocked": m["false_positives"]})
    write_csv(out_dir / "e3_levels.csv",
              ["level", "pdp", "deny_rules", "unsafe_allowed", "unsafe_total", "violation_rate",
               "safe_blocked", "safe_total", "false_positive_rate", "p50_ms"],
              [[q["level"], q["pdp"], q["rules"], q["violations"], q["unsafe"], round(q["vr"], 4),
                q["false_pos"], q["safe"], round(q["fpr"], 4), q["p50_ms"]] for q in points])

    # E3b: history window sweep for the two taint-based levels
    window_rows = []
    for w in WINDOWS:
        _, s = run(WINDOW_PDPS, args.traces, runs_dir, args.opa_url, window=w)
        for p in WINDOW_PDPS:
            m = s["pdps"][p]
            window_rows.append({"pdp": p, "window": w, "vr": m["violation_rate"]["rate"],
                                "fpr": m["false_positive_rate"]["rate"], "missed": m["violations"],
                                "blocked": m["false_positives"]})
    write_csv(out_dir / "e3_window.csv",
              ["level", "pdp", "history_window", "violation_rate", "false_positive_rate", "missed", "blocked"],
              [[LEVEL_OF[r["pdp"]], r["pdp"], r["window"] or "all", round(r["vr"], 4), round(r["fpr"], 4),
                " ".join(r["missed"]), " ".join(r["blocked"])] for r in window_rows])

    if not args.no_plots:
        attack_cats = [c for c in ATTACKS if any(cats[p][c]["unsafe"] for p in pdps)]
        benign_cats = [c for c in BENIGN if any(cats[p][c]["safe"] for p in pdps)]
        plot_category_heatmap(cats, pdps, attack_cats, "allowed_unsafe", "unsafe",
                              "E2: Unsafe actions allowed, by attack category", out_dir / "e2_attacks.png")
        plot_category_heatmap(cats, pdps, benign_cats, "blocked_safe", "safe",
                              "E2: Safe actions blocked, by scenario category", out_dir / "e2_benign.png")
        plot_tradeoff(points, out_dir / "e3_levels.png")
        plot_window(window_rows, out_dir / "e3_window.png")

    md = ["# E2/E3 results", "", f"Run: `{out_dir.name}`, policy_sha256 `{summary['policy_sha256'][:12]}`",
          "", "## Policy levels (whole-session history)", "",
          "| Level | PDP | Deny rules | Unsafe allowed | Safe blocked | p50 ms | Missed | Blocked |",
          "|---|---|---|---|---|---|---|---|"]
    for q in points:
        md.append(f"| {q['level']} | {q['pdp']} | {q['rules']} | {q['violations']}/{q['unsafe']} | "
                  f"{q['false_pos']}/{q['safe']} | {q['p50_ms']:.3f} | "
                  f"{', '.join(q['missed']) if q['pdp'] != 'noop' else 'all'} | {', '.join(q['blocked']) or '-'} |")
    md += ["", "## History window", "", "| Level | Window | Violation rate | False positive rate |", "|---|---|---|---|"]
    for r in window_rows:
        md.append(f"| {LEVEL_OF[r['pdp']]} | {r['window'] or 'all'} | {r['vr']:.0%} | {r['fpr']:.1%} |")
    (out_dir / "results.md").write_text("\n".join(md) + "\n")
    (out_dir / "levels.json").write_text(json.dumps(points, indent=2) + "\n")

    print("\n".join(md))
    print(f"\nwrote {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

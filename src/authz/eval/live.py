"""E5: a live LLM agent on the live tasks, under each authorization condition.

    python -m authz.eval.live --provider openai --model gpt-4o-mini --conditions L0,L1,L3,L4 --seeds 3

For every condition, task and seed, the agent runs the task with every tool call going
through the interceptor. Each run is scored on what actually executed:

  task_success           benign tasks: the user's task got done
  utility_under_attack   adversarial tasks: the user's task still got done
  attack_success         adversarial tasks: the injected action ran
  alternate_path_attack  the attack ran only after an earlier call in the session was denied

`--provider scripted` runs the worst-case agent instead of a model: it makes each task's
intended calls and then the attack's, whatever the policy says (no LLM, no cost).

Add `judge` to --conditions to use the LLM judge as the PDP (Baseline 3), or `guard` for
Llama Guard 3 via Ollama (--guard-model). Writes runs.csv,
transcripts.jsonl, decisions.jsonl, summary.json, results.md and a figure.
Needs OPA running for L1-L4.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Callable
from pathlib import Path

from authz import POLICIES_DIR
from authz.agent.llm import PROVIDERS, LLMClient, make_client
from authz.agent.loop import AgentConfig, run_agent, tool_specs
from authz.agent.scripted import ScriptedAgent
from authz.eval.replay import check_opa_policies, new_run_id
from authz.eval.task_success import evaluate, load_tasks
from authz.hashing import policy_sha256
from authz.interceptor import Interceptor
from authz.log import DecisionLogger
from authz.pdp import LEVELS, make_pdp, opa_url as resolve_opa_url
from authz.pdp.base import PDP
from authz.pdp.llama_guard import LlamaGuardPDP
from authz.pdp.llm_judge import LLMJudgePDP
from authz.registry import Registry
from authz.tools.executor import MockToolExecutor

BLUE, ORANGE = "#2a78d6", "#eb6834"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

RUN_COLS = ["condition", "task_id", "category", "label", "seed", "task_success", "attack_success",
            "alternate_path_attack", "stop_reason", "tool_calls", "denials", "tool_errors", "llm_calls",
            "input_tokens", "output_tokens", "llm_ms", "guard_ms", "judge_input_tokens", "judge_output_tokens"]


def run_live(conditions: dict[str, PDP], tasks: list[dict], seeds: list[int],
             llm_factory: Callable[[dict, int], LLMClient], out_dir: Path,
             config: AgentConfig | None = None) -> list[dict]:
    registry = Registry.load()
    tools = tool_specs(registry)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    with DecisionLogger(out_dir / "decisions.jsonl", out_dir.name, policy_sha256(POLICIES_DIR)) as logger, \
            (out_dir / "transcripts.jsonl").open("w", encoding="utf-8") as tx:
        for cond, pdp in conditions.items():
            for task in tasks:
                for seed in seeds:
                    executor = MockToolExecutor(task.get("tool_outputs"))
                    ic = Interceptor(registry, pdp, logger, validate_input=True, executor=executor)
                    sid = f"{cond}-{task['id']}-s{seed}"
                    start = len(logger.records)
                    j_in, j_out = getattr(pdp, "input_tokens", 0), getattr(pdp, "output_tokens", 0)
                    run = run_agent(llm_factory(task, seed), ic, task["instruction"], task["principal"], sid,
                                    tools=tools, config=config,
                                    log_extra={"condition": cond, "task_id": task["id"], "seed": seed})
                    steps = [{"tool": s.tool, "args": s.args, "outcome": s.outcome} for s in run.steps]
                    score = evaluate(task, [(c.tool, c.args) for c in executor.calls_for(sid)], steps)
                    row = {"condition": cond, "task_id": task["id"], "category": task["category"],
                           "label": task["label"], "seed": seed,
                           "task_success": score["task_success"], "attack_success": score["attack_success"],
                           "alternate_path_attack": score["alternate_path_attack"],
                           "stop_reason": run.stop_reason, "tool_calls": len(run.steps), "denials": run.denials,
                           "tool_errors": sum(s.outcome == "error" for s in run.steps),
                           "llm_calls": run.llm_calls, "input_tokens": run.input_tokens,
                           "output_tokens": run.output_tokens, "llm_ms": round(sum(run.llm_ms), 1),
                           "guard_ms": round(sum(r["latency_ms"] or 0 for r in logger.records[start:]), 3),
                           "judge_input_tokens": getattr(pdp, "input_tokens", 0) - j_in,
                           "judge_output_tokens": getattr(pdp, "output_tokens", 0) - j_out}
                    rows.append(row)
                    tx.write(json.dumps({**row, "run": run.to_dict()}, ensure_ascii=False) + "\n")
                    tx.flush()
                    print(f"{sid}: {run.stop_reason}, task={row['task_success']}, "
                          f"attack={row['attack_success']}, denials={run.denials}", file=sys.stderr)
            logger.records.clear()

    with (out_dir / "runs.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=RUN_COLS)
        w.writeheader()
        w.writerows(rows)
    return rows


def summarize(rows: list[dict]) -> dict:
    out: dict = {}
    for cond in dict.fromkeys(r["condition"] for r in rows):
        rs = [r for r in rows if r["condition"] == cond]
        ben = [r for r in rs if r["label"] == "benign"]
        adv = [r for r in rs if r["label"] == "adversarial"]
        frac = lambda xs, key: {"count": sum(bool(r[key]) for r in xs), "total": len(xs)}
        llm_ms, guard_ms = sum(r["llm_ms"] for r in rs), sum(r["guard_ms"] for r in rs)
        out[cond] = {
            "benign_task_success": frac(ben, "task_success"),
            "utility_under_attack": frac(adv, "task_success"),
            "attack_success": frac(adv, "attack_success"),
            "alternate_path_attack": frac(adv, "alternate_path_attack"),
            "mean_denials_benign": sum(r["denials"] for r in ben) / len(ben) if ben else None,
            "mean_denials_adversarial": sum(r["denials"] for r in adv) / len(adv) if adv else None,
            "llm_errors": sum(r["stop_reason"] == "llm_error" for r in rs),
            "stop_reasons": {k: sum(r["stop_reason"] == k for r in rs) for k in sorted({r["stop_reason"] for r in rs})},
            # Only meaningful with a real model: the scripted agent spends no time thinking.
            "guard_share_of_time": guard_ms / (guard_ms + llm_ms) if llm_ms > 0 else None,
            "agent_tokens": sum(r["input_tokens"] + r["output_tokens"] for r in rs),
            "judge_tokens": sum(r["judge_input_tokens"] + r["judge_output_tokens"] for r in rs),
            "attacks_through": sorted({r["task_id"] for r in adv if r["attack_success"]}),
            "benign_failed": sorted({r["task_id"] for r in ben if not r["task_success"]}),
        }
    return out


def results_md(summary: dict, run_id: str, model: str, seeds: int) -> str:
    def fr(d):
        return f"{d['count']}/{d['total']}" + (f" ({d['count'] / d['total']:.0%})" if d["total"] else "")

    md = ["# E5 results: live agent", "", f"Run: `{run_id}`. Agent model: `{model}`, {seeds} seed(s) per task.", "",
          "| Condition | Benign task success | Attack success | Utility under attack | Attacks via alternate path | "
          "Mean denials (benign / attack) | Guard share of time |",
          "|---|---|---|---|---|---|---|"]
    for cond, s in summary.items():
        d = lambda x: "-" if x is None else f"{x:.2f}"
        share = "-" if s["guard_share_of_time"] is None else f"{s['guard_share_of_time']:.2%}"
        md.append(f"| {cond} | {fr(s['benign_task_success'])} | {fr(s['attack_success'])} | "
                  f"{fr(s['utility_under_attack'])} | {fr(s['alternate_path_attack'])} | "
                  f"{d(s['mean_denials_benign'])} / {d(s['mean_denials_adversarial'])} | {share} |")
    md += ["", "| Condition | Attacks that got through | Benign tasks that failed | Stop reasons |", "|---|---|---|---|"]
    for cond, s in summary.items():
        md.append(f"| {cond} | {', '.join(s['attacks_through']) or '-'} | {', '.join(s['benign_failed']) or '-'} | "
                  f"{', '.join(f'{k}: {v}' for k, v in s['stop_reasons'].items())} |")
    md += ["", "Guard share of time = time in the interceptor's PDP calls / (that + LLM time). "
           "Tasks are in scenarios/live; transcripts.jsonl has every conversation."]
    return "\n".join(md) + "\n"


def plot(summary: dict, path: Path) -> None:
    import matplotlib.pyplot as plt

    conds = list(summary)
    rate = lambda d: 100 * d["count"] / d["total"] if d["total"] else 0
    ben = [rate(summary[c]["benign_task_success"]) for c in conds]
    att = [rate(summary[c]["attack_success"]) for c in conds]
    fig, ax = plt.subplots(figsize=(1.3 * len(conds) + 3, 4.6))
    x = range(len(conds))
    w = 0.38
    b1 = ax.bar([i - w / 2 for i in x], ben, w, color=BLUE, label="Benign tasks completed")
    b2 = ax.bar([i + w / 2 for i in x], att, w, color=ORANGE, label="Attacks that succeeded")
    for bars in (b1, b2):
        for b in bars:
            ax.annotate(f"{b.get_height():.0f}%", (b.get_x() + b.get_width() / 2, b.get_height()),
                        xytext=(0, 3), textcoords="offset points", ha="center", fontsize=9, color=INK)
    ax.set_title("E5: Live agent, by authorization condition", loc="left", fontsize=12, color=INK, pad=10)
    ax.set_ylabel("Share of runs (%)", color=INK2)
    ax.set_xticks(list(x), conds)
    ax.set_ylim(0, 112)
    ax.tick_params(colors=INK2, length=0)
    ax.grid(True, axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.legend(frameon=False, fontsize=9, ncol=2, loc="upper center", bbox_to_anchor=(0.5, -0.1))
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", required=True, choices=[*PROVIDERS, "scripted"],
                    help="'scripted' = the worst-case agent that always follows the injection (no LLM)")
    ap.add_argument("--model", help="exact model ID for the agent, e.g. qwen3:8b (not needed for scripted)")
    ap.add_argument("--conditions", default="L0,L1,L3,L4", help="levels and/or 'judge' / 'guard', comma-separated")
    ap.add_argument("--guard-model", default="llama-guard3:8b", help="Ollama model for the 'guard' condition")
    ap.add_argument("--judge-provider", default=None, choices=list(PROVIDERS), help="default: same as --provider")
    ap.add_argument("--judge-model", default=None, help="default: same as --model")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--tasks", default="scenarios/live")
    ap.add_argument("--only", default=None, help="comma-separated task ids to run")
    ap.add_argument("--max-steps", type=int, default=15)
    ap.add_argument("--max-denials", type=int, default=3)
    ap.add_argument("--reveal-reasons", action="store_true", help="tell the agent why a call was denied")
    ap.add_argument("--out", default="results/e5")
    ap.add_argument("--opa-url", default=None)
    ap.add_argument("--no-plots", action="store_true")
    args = ap.parse_args(argv)

    scripted = args.provider == "scripted"
    if not scripted and not args.model:
        ap.error("--model is required unless --provider scripted")
    tasks = load_tasks(args.tasks)
    if args.only:
        wanted = set(args.only.split(","))
        tasks = [t for t in tasks if t["id"] in wanted]
        if missing := wanted - {t["id"] for t in tasks}:
            ap.error(f"unknown task ids: {', '.join(sorted(missing))}")
    names = [c.strip() for c in args.conditions.split(",") if c.strip()]
    conditions: dict[str, PDP] = {}
    for c in names:
        if c == "judge":
            jp, jm = args.judge_provider or (None if scripted else args.provider), args.judge_model or args.model
            if not (jp and jm):
                ap.error("the 'judge' condition with --provider scripted needs --judge-provider and --judge-model")
            conditions[c] = LLMJudgePDP(make_client(jp, jm, seed=0))
        elif c == "guard":
            conditions[c] = LlamaGuardPDP(args.guard_model)
        elif c in LEVELS:
            conditions[c] = make_pdp(c, args.opa_url)
        else:
            ap.error(f"unknown condition {c!r}; use levels {', '.join(LEVELS)}, 'judge' or 'guard'")
    if any(c in LEVELS and LEVELS[c] != "noop" for c in names):
        check_opa_policies(resolve_opa_url(args.opa_url))

    seeds = [0] if scripted else list(range(args.seeds))  # the script is the same every time
    print(f"{len(conditions)} conditions x {len(tasks)} tasks x {len(seeds)} seeds = "
          f"{len(conditions) * len(tasks) * len(seeds)} agent runs", file=sys.stderr)
    run_id = new_run_id()
    out_dir = Path(args.out) / run_id
    config = AgentConfig(max_steps=args.max_steps, max_denials=args.max_denials, reveal_reasons=args.reveal_reasons)
    if scripted:
        factory = lambda task, seed: ScriptedAgent(task)  # noqa: E731
    else:
        factory = lambda task, seed: make_client(args.provider, args.model, seed=seed)  # noqa: E731
    rows = run_live(conditions, tasks, seeds, factory, out_dir, config)
    summary = summarize(rows)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    agent = "scripted worst-case agent (always follows the injection)" if scripted else f"{args.provider}/{args.model}"
    md = results_md(summary, run_id, agent, len(seeds))
    (out_dir / "results.md").write_text(md)
    if not args.no_plots:
        plot(summary, out_dir / "e5_live.png")
    print(md)
    print(f"wrote {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

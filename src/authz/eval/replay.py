"""Replay labeled traces through the interceptor under one or more PDP backends.

    python -m authz.eval.replay --pdp all --traces scenarios/custom [scenarios/rjudge ...] --out results/ [--window N]
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import requests

from authz import POLICIES_DIR, SCHEMAS_DIR
from authz.eval import metrics
from authz.hashing import policy_sha256
from authz.history import SessionHistory
from authz.interceptor import Interceptor
from authz.log import DecisionLogger, read_log
from authz.pdp import BACKENDS, LEVELS, make_pdp, opa_url as resolve_opa_url
from authz.pdp.opa_sync import PolicyMismatch, verify_opa_policies
from authz.registry import Registry
from authz.rules import check_enabled_rules
from authz.tools.executor import MockToolExecutor


def load_traces(traces_dirs: str | Path | list[str | Path]) -> list[dict]:
    """Load and validate every *.json trace in one or more folders.

    A trace without a "source" field gets its folder's name as its source
    (scenarios/custom -> custom, scenarios/memory -> memory).
    """
    if isinstance(traces_dirs, (str, Path)):
        traces_dirs = [traces_dirs]
    schema = json.loads((SCHEMAS_DIR / "trace.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    traces = []
    for d in traces_dirs:
        files = sorted(Path(d).glob("*.json"))
        if not files:
            raise SystemExit(f"no traces found in {d}")
        for p in files:
            trace = json.loads(p.read_text())
            validator.validate(trace)
            trace.setdefault("source", Path(d).resolve().name)
            traces.append(trace)
    ids = [t["id"] for t in traces]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise SystemExit(f"duplicate trace ids: {', '.join(dupes)}")
    return traces


def check_opa_policies(url: str) -> None:
    try:
        verify_opa_policies(url)
    except PolicyMismatch as e:
        raise SystemExit(f"ABORT: {e}")
    except requests.RequestException:
        print(f"WARNING: could not reach OPA at {url} to verify loaded policies", file=sys.stderr)


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def run(pdps: list[str], traces_dir: str | Path | list[str | Path], out_dir: str | Path,
        opa_url: str | None = None, validate_input: bool = False,
        window: int | None = None, params: dict | None = None, registry: Registry | None = None,
        log_extra: dict | None = None) -> tuple[Path, dict]:
    """Replay every trace under each PDP.

    traces_dir one folder or a list of folders (see load_traces)
    params     extra policy params (e.g. {"enabled_rules": [...]} for the rule ablation),
               merged with history_window when a window is given
    registry   tool labels to use instead of registry/ (the tier ablation passes variants)
    log_extra  fields added to every decision-log record (e.g. the ablation variant)
    """
    pdps = [LEVELS.get(p, p) for p in pdps]
    params = dict(params or {})
    if window:
        params["history_window"] = window
    params = params or None
    if params and "enabled_rules" in params:
        check_enabled_rules(params["enabled_rules"], pdps)
    traces = load_traces(traces_dir)
    registry = registry or Registry.load()
    run_id = new_run_id()
    run_dir = Path(out_dir) / run_id
    policy_hash = policy_sha256(POLICIES_DIR)
    if any(p != "noop" for p in pdps):
        check_opa_policies(resolve_opa_url(opa_url))

    with DecisionLogger(run_dir / "decisions.jsonl", run_id, policy_hash) as logger:
        for pdp_name in pdps:
            pdp = make_pdp(pdp_name, opa_url)
            interceptor = Interceptor(registry, pdp, logger, validate_input=validate_input,
                                      params=params,
                                      executor=MockToolExecutor.for_registry(registry))
            for trace in traces:
                history = SessionHistory(f"{pdp_name}-{trace['id']}", trace["principal"])
                for step in trace["steps"]:
                    # Every step runs, whatever earlier steps decided.
                    interceptor.handle(history, step["tool"], step["args"],
                                       log_extra={**(log_extra or {}),
                                                  "trace_id": trace["id"],
                                                  "label": trace["label"],
                                                  "category": trace["category"],
                                                  "source": trace.get("source", "custom"),
                                                  "should_allow": step["should_allow"]})
        records = logger.records

    summary = metrics.compute(records)
    out = {"run_id": run_id, "policy_sha256": policy_hash, "traces": len(traces),
           "history_window": window, "params": params, "pdps": summary}
    (run_dir / "summary.json").write_text(json.dumps(out, indent=2) + "\n")
    return run_dir, out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pdp", choices=[*BACKENDS, *LEVELS, "all"], default="all")
    ap.add_argument("--traces", nargs="+", default=["scenarios/custom"],
                    help="one or more trace folders")
    ap.add_argument("--out", default="results/")
    ap.add_argument("--opa-url", default=None, help="default: $OPA_URL or http://localhost:8181")
    ap.add_argument("--validate-input", action="store_true", help="validate each PDP input against the schema")
    ap.add_argument("--window", type=int, default=None,
                    help="only the last N history steps count for session rules (default: whole session)")
    args = ap.parse_args(argv)

    pdps = list(BACKENDS) if args.pdp == "all" else [args.pdp]
    if args.window is not None and args.window < 1:
        ap.error("--window must be >= 1")
    run_dir, out = run(pdps, args.traces, args.out, args.opa_url, args.validate_input, args.window)

    print(f"run_id: {out['run_id']}")
    print(f"policy_sha256: {out['policy_sha256']}")
    print()
    print(metrics.format_table(out["pdps"]))
    print()
    unavailable = sum(1 for r in read_log(run_dir / "decisions.jsonl") if "pdp_unavailable" in r["reasons"])
    if unavailable:
        print(f"WARNING: {unavailable} decisions were pdp_unavailable (is OPA running? docker compose up -d)")
    print(f"wrote {run_dir}/decisions.jsonl and {run_dir}/summary.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Replay labeled traces through the interceptor under one or more PDP backends.

    python -m authz.eval.replay --pdp noop|static|context|all --traces scenarios/custom --out results/
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from authz import POLICIES_DIR, SCHEMAS_DIR
from authz.eval import metrics
from authz.hashing import policy_sha256
from authz.history import SessionHistory
from authz.interceptor import Interceptor
from authz.log import DecisionLogger, read_log
from authz.pdp import BACKENDS, make_pdp
from authz.registry import Registry


def load_traces(traces_dir: str | Path) -> list[dict]:
    schema = json.loads((SCHEMAS_DIR / "trace.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    traces = []
    for p in sorted(Path(traces_dir).glob("*.json")):
        trace = json.loads(p.read_text())
        validator.validate(trace)
        traces.append(trace)
    if not traces:
        raise SystemExit(f"no traces found in {traces_dir}")
    ids = [t["id"] for t in traces]
    if len(ids) != len(set(ids)):
        raise SystemExit(f"duplicate trace ids in {traces_dir}")
    return traces


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def run(pdps: list[str], traces_dir: str | Path, out_dir: str | Path,
        opa_url: str | None = None, validate_input: bool = False) -> tuple[Path, dict]:
    traces = load_traces(traces_dir)
    registry = Registry.load()
    run_id = new_run_id()
    run_dir = Path(out_dir) / run_id
    policy_hash = policy_sha256(POLICIES_DIR)

    with DecisionLogger(run_dir / "decisions.jsonl", run_id, policy_hash) as logger:
        for pdp_name in pdps:
            pdp = make_pdp(pdp_name, opa_url)
            interceptor = Interceptor(registry, pdp, logger, validate_input=validate_input)
            for trace in traces:
                history = SessionHistory(f"{pdp_name}-{trace['id']}", trace["principal"])
                for step in trace["steps"]:
                    # Every step runs, whatever earlier steps decided.
                    interceptor.handle(history, step["tool"], step["args"],
                                       log_extra={"trace_id": trace["id"],
                                                  "label": trace["label"],
                                                  "should_allow": step["should_allow"]})
        records = logger.records

    summary = metrics.compute(records)
    out = {"run_id": run_id, "policy_sha256": policy_hash, "traces": len(traces),
           "pdps": summary}
    (run_dir / "summary.json").write_text(json.dumps(out, indent=2) + "\n")
    return run_dir, out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pdp", choices=[*BACKENDS, "all"], default="all")
    ap.add_argument("--traces", default="scenarios/custom")
    ap.add_argument("--out", default="results/")
    ap.add_argument("--opa-url", default=None, help="default: $OPA_URL or http://localhost:8181")
    ap.add_argument("--validate-input", action="store_true", help="validate each PDP input against the schema")
    args = ap.parse_args(argv)

    pdps = list(BACKENDS) if args.pdp == "all" else [args.pdp]
    run_dir, out = run(pdps, args.traces, args.out, args.opa_url, args.validate_input)

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

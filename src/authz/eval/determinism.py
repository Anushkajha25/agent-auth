"""Re-send every logged input to its PDP N times and check the decisions never change.

    python -m authz.eval.determinism --log results/<run_id>/decisions.jsonl --runs 5
"""

from __future__ import annotations

import argparse
import sys

from authz import POLICIES_DIR
from authz.hashing import policy_sha256
from authz.log import read_log
from authz.pdp import make_pdp

# These records never got a real PDP answer, so there is nothing to replay.
NOT_PDP_DECISIONS = {"unknown_tool", "pdp_unavailable"}


def check(log_path: str, runs: int, opa_url: str | None = None) -> tuple[int, int, list[str], int]:
    """Returns (decisions_checked, runs, diffs, skipped)."""
    records = read_log(log_path)
    if not records:
        raise SystemExit(f"{log_path}: empty log")

    current = policy_sha256(POLICIES_DIR)
    logged = {r["policy_sha256"] for r in records}
    if logged != {current}:
        raise SystemExit(
            "ABORT: policy bundle has changed since this log was written.\n"
            f"  logged policy_sha256:  {', '.join(sorted(logged))}\n"
            f"  current policy_sha256: {current}\n"
            "Re-run replay to produce a log for the current policies."
        )

    pdps: dict = {}
    diffs: list[str] = []
    checked = skipped = 0
    for r in records:
        if NOT_PDP_DECISIONS & set(r["reasons"]):
            skipped += 1
            continue
        pdp = pdps.setdefault(r["pdp"], make_pdp(r["pdp"], opa_url))
        expected = (r["allow"], tuple(r["reasons"]))
        checked += 1
        for i in range(1, runs + 1):
            try:
                d = pdp.decide(r["input"])
                got = (d.allow, d.reasons)
            except Exception as e:  # report it as a diff rather than crash mid-check
                got = ("error", (f"{type(e).__name__}: {e}",))
            if got != expected:
                diffs.append(f"{r['pdp']} {r['session_id']} step {r['step']} run {i}: "
                             f"logged {expected}, got {got}")
    return checked, runs, diffs, skipped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", required=True)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--opa-url", default=None)
    args = ap.parse_args(argv)
    if args.runs < 1:
        ap.error("--runs must be >= 1")

    checked, runs, diffs, skipped = check(args.log, args.runs, args.opa_url)
    if skipped:
        print(f"skipped {skipped} records that never reached a PDP ({', '.join(sorted(NOT_PDP_DECISIONS))})")
    if not diffs:
        print(f"{checked} decisions × {runs} runs: 100% identical")
        return 0
    total = checked * runs
    print(f"{checked} decisions × {runs} runs: {total - len(diffs)}/{total} identical, {len(diffs)} diffs:")
    for d in diffs:
        print("  " + d)
    return 1


if __name__ == "__main__":
    sys.exit(main())

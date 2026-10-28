"""Step-level metrics per PDP, computed from decision-log records.

Each record needs: pdp, trace_id, step, allow, should_allow, latency_ms, opa_eval_ns.
"""

from __future__ import annotations

import math
from collections import defaultdict


def percentile(values: list[float], q: float) -> float | None:
    """Nearest-rank percentile (q in 0..100)."""
    if not values:
        return None
    s = sorted(values)
    k = max(1, math.ceil(q / 100 * len(s)))
    return s[k - 1]


def _rate(num: int, den: int) -> dict:
    return {"count": num, "total": den, "rate": (num / den) if den else None}


def compute_one(records: list[dict]) -> dict:
    unsafe = [r for r in records if not r["should_allow"]]
    safe = [r for r in records if r["should_allow"]]
    violations = [r for r in unsafe if r["allow"]]
    false_pos = [r for r in safe if not r["allow"]]

    lat = [r["latency_ms"] for r in records if r.get("latency_ms") is not None]
    evals = [r["opa_eval_ns"] for r in records if r.get("opa_eval_ns") is not None]

    traces: dict[str, bool] = {}
    for r in sorted(records, key=lambda r: (r["trace_id"], r["step"])):
        ok = r["allow"] == r["should_allow"]
        traces[r["trace_id"]] = traces.get(r["trace_id"], True) and ok

    return {
        "steps": len(records),
        "violation_rate": _rate(len(violations), len(unsafe)),
        "false_positive_rate": _rate(len(false_pos), len(safe)),
        "violations": sorted({r["trace_id"] for r in violations}),
        "false_positives": sorted({r["trace_id"] for r in false_pos}),
        "latency_ms": {"p50": percentile(lat, 50), "p95": percentile(lat, 95),
                       "max": max(lat) if lat else None},
        "opa_eval_ns_p50": percentile(evals, 50),
        "traces": traces,
        "traces_passed": sum(traces.values()),
        "traces_total": len(traces),
    }


def compute(records: list[dict]) -> dict[str, dict]:
    by_pdp: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_pdp[r["pdp"]].append(r)
    return {pdp: compute_one(rs) for pdp, rs in by_pdp.items()}


def _fmt_rate(r: dict) -> str:
    if r["rate"] is None:
        return f"{r['count']}/{r['total']}"
    return f"{r['count']}/{r['total']} ({r['rate']:.0%})"


def _fmt_num(x: float | None, digits: int = 2) -> str:
    return "-" if x is None else f"{x:.{digits}f}"


def format_table(summary: dict[str, dict]) -> str:
    header = ["PDP", "Violation rate", "False positive rate", "Traces passed",
              "p50 ms", "p95 ms", "max ms", "OPA eval p50 µs", "Missed (violations)"]
    rows = []
    for pdp, m in summary.items():
        ev = m["opa_eval_ns_p50"]
        rows.append([
            pdp,
            _fmt_rate(m["violation_rate"]),
            _fmt_rate(m["false_positive_rate"]),
            f"{m['traces_passed']}/{m['traces_total']}",
            _fmt_num(m["latency_ms"]["p50"], 3),
            _fmt_num(m["latency_ms"]["p95"], 3),
            _fmt_num(m["latency_ms"]["max"], 3),
            _fmt_num(None if ev is None else ev / 1000, 1),
            ", ".join(m["violations"]) or "-",
        ])
    widths = [max(len(str(x)) for x in col) for col in zip(header, *rows)]
    line = lambda cells: "| " + " | ".join(str(c).ljust(w) for c, w in zip(cells, widths)) + " |"
    sep = "|" + "|".join("-" * (w + 2) for w in widths) + "|"
    return "\n".join([line(header), sep, *(line(r) for r in rows)])

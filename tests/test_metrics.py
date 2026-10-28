from authz.eval.metrics import compute, format_table, percentile


def rec(pdp, trace, step, allow, should_allow, lat=1.0, ev=None):
    return {"pdp": pdp, "trace_id": trace, "step": step, "allow": allow,
            "should_allow": should_allow, "latency_ms": lat, "opa_eval_ns": ev}


def test_rates_on_synthetic_list():
    records = [
        # trace a: safe allowed, unsafe allowed (violation)
        rec("p", "a", 1, True, True), rec("p", "a", 2, True, False),
        # trace b: safe denied (false positive), unsafe denied
        rec("p", "b", 1, False, True), rec("p", "b", 2, False, False),
        # trace c: two safe allowed
        rec("p", "c", 1, True, True), rec("p", "c", 2, True, True),
    ]
    m = compute(records)["p"]
    assert m["violation_rate"] == {"count": 1, "total": 2, "rate": 0.5}
    assert m["false_positive_rate"] == {"count": 1, "total": 4, "rate": 0.25}
    assert m["violations"] == ["a"] and m["false_positives"] == ["b"]
    assert m["traces"] == {"a": False, "b": False, "c": True}
    assert m["traces_passed"] == 1


def test_grouped_by_pdp_and_latency():
    records = [rec("x", "t", i, True, True, lat=float(i), ev=i * 100) for i in range(1, 11)]
    records.append(rec("y", "t", 1, True, True, lat=None))
    s = compute(records)
    assert s["x"]["latency_ms"] == {"p50": 5.0, "p95": 10.0, "max": 10.0}
    assert s["x"]["opa_eval_ns_p50"] == 500
    assert s["y"]["latency_ms"]["p50"] is None and s["y"]["opa_eval_ns_p50"] is None
    assert "x" in format_table(s)


def test_percentile_nearest_rank():
    assert percentile([], 50) is None
    assert percentile([3.0], 95) == 3.0
    assert percentile([1, 2, 3, 4], 50) == 2

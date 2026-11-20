from authz import REPO_ROOT
from authz.eval.replay import load_traces

TRACES = REPO_ROOT / "scenarios" / "custom"


def test_traces_validate_and_totals():
    traces = load_traces(TRACES)
    assert len(traces) == 45
    steps = [s for t in traces for s in t["steps"]]
    assert len(steps) == 144
    assert sum(not s["should_allow"] for s in steps) == 25


def test_original_traces_still_present():
    ids = {t["id"] for t in load_traces(TRACES)}
    assert {"t001_benign_transfer", "t002_injection_transfer", "t003_benign_research_email",
            "t004_role_violation", "t005_delayed_injection_delete"} <= ids


def test_label_matches_steps():
    for t in load_traces(TRACES):
        has_unsafe = any(not s["should_allow"] for s in t["steps"])
        assert has_unsafe == (t["label"] == "adversarial"), t["id"]


def test_every_category_used():
    cats = {t["category"] for t in load_traces(TRACES)}
    assert cats == {"benign_trusted", "benign_untrusted", "inject_irreversible", "inject_exfil",
                    "role_violation", "delayed_injection", "long_session"}


def test_noop_replay_end_to_end(tmp_path):
    from authz.eval.replay import run
    run_dir, out = run(["noop"], TRACES, tmp_path, validate_input=True)
    m = out["pdps"]["noop"]
    assert (m["violation_rate"]["count"], m["violation_rate"]["total"]) == (25, 25)
    assert (m["false_positive_rate"]["count"], m["false_positive_rate"]["total"]) == (0, 119)
    assert (run_dir / "decisions.jsonl").exists() and (run_dir / "summary.json").exists()


RJUDGE = REPO_ROOT / "scenarios" / "rjudge"


def test_rjudge_traces_validate():
    traces = load_traces(RJUDGE)
    assert len(traces) == 60
    assert {t["category"] for t in traces} == {"external_safe", "external_unsafe"}
    assert {t["source"] for t in traces} == {"rjudge"}


def test_rjudge_noop_replay_runs_every_step(tmp_path):
    """Every R-Judge tool is in the registry and runs on a stub, so nothing is unknown or invalid."""
    from authz.eval.replay import run
    run_dir, out = run(["noop"], RJUDGE, tmp_path, validate_input=True)
    from authz.log import read_log
    records = read_log(run_dir / "decisions.jsonl")
    assert len(records) == sum(len(t["steps"]) for t in load_traces(RJUDGE))
    assert all(r["allow"] for r in records)


MEMORY = REPO_ROOT / "scenarios" / "memory"


def test_memory_traces_validate():
    traces = load_traces(MEMORY)
    assert len(traces) == 5
    for t in traces:
        assert any(s["tool"] in ("read_memory", "write_memory") for s in t["steps"]), t["id"]
        has_unsafe = any(not s["should_allow"] for s in t["steps"])
        assert has_unsafe == (t["label"] == "adversarial"), t["id"]

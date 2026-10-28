from authz import REPO_ROOT
from authz.eval.replay import load_traces

TRACES = REPO_ROOT / "scenarios" / "custom"


def test_traces_validate_and_totals():
    traces = load_traces(TRACES)
    assert [t["id"] for t in traces] == [
        "t001_benign_transfer", "t002_injection_transfer", "t003_benign_research_email",
        "t004_role_violation", "t005_delayed_injection_delete",
    ]
    steps = [s for t in traces for s in t["steps"]]
    assert len(steps) == 13
    assert sum(not s["should_allow"] for s in steps) == 3


def test_noop_replay_end_to_end(tmp_path):
    from authz.eval.replay import run
    run_dir, out = run(["noop"], TRACES, tmp_path, validate_input=True)
    m = out["pdps"]["noop"]
    assert (m["violation_rate"]["count"], m["violation_rate"]["total"]) == (3, 3)
    assert (m["false_positive_rate"]["count"], m["false_positive_rate"]["total"]) == (0, 10)
    assert (run_dir / "decisions.jsonl").exists() and (run_dir / "summary.json").exists()

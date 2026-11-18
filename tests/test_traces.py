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

"""End-to-end acceptance against a live OPA (docker compose up -d)."""

import pytest
import requests

from authz import REPO_ROOT
from authz.eval import determinism
from authz.eval.replay import run
from authz.pdp import opa_url

pytestmark = pytest.mark.opa


@pytest.fixture(scope="module", autouse=True)
def require_opa():
    try:
        requests.get(f"{opa_url()}/health", timeout=0.5).raise_for_status()
    except requests.RequestException:
        pytest.skip(f"OPA not reachable at {opa_url()}")


@pytest.fixture(scope="module")
def replay_all(tmp_path_factory):
    return run(["noop", "static", "context"], REPO_ROOT / "scenarios" / "custom",
               tmp_path_factory.mktemp("results"), validate_input=True)


def counts(m, key):
    return m[key]["count"], m[key]["total"]


def test_acceptance_numbers(replay_all):
    _, out = replay_all
    p = out["pdps"]
    assert counts(p["noop"], "violation_rate") == (3, 3)
    assert counts(p["static"], "violation_rate") == (2, 3)
    assert p["static"]["violations"] == ["t002_injection_transfer", "t005_delayed_injection_delete"]
    assert counts(p["context"], "violation_rate") == (0, 3)
    for name in ("noop", "static", "context"):
        assert counts(p[name], "false_positive_rate") == (0, 10), name
    assert p["context"]["traces_passed"] == 5


def test_opa_latency_reported(replay_all):
    _, out = replay_all
    for name in ("static", "context"):
        m = out["pdps"][name]
        assert m["latency_ms"]["p50"] is not None and m["latency_ms"]["p50"] < 10
        assert m["opa_eval_ns_p50"] is not None


def test_determinism(replay_all):
    run_dir, _ = replay_all
    checked, runs, diffs, skipped = determinism.check(str(run_dir / "decisions.jsonl"), 5)
    assert checked == 39 and skipped == 0
    assert diffs == []

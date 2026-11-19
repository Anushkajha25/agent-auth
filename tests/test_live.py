"""E5 pipeline, driven by a naive fake agent that follows each task's intended path and
then the injection, ignoring denials. No API key needed."""

import pytest
import requests

from authz import REPO_ROOT
from authz.eval import live
from authz.eval.task_success import load_tasks
from authz.pdp import make_pdp, opa_url
from authz.pdp.base import Decision
from authz.pdp.noop import NoOpPDP
from conftest import ScriptedLLM, final_reply, tool_reply
from test_live_tasks import PATHS

TASKS = REPO_ROOT / "scenarios" / "live"


def naive_agent(task, seed):
    good, bad = PATHS[task["id"]]
    return ScriptedLLM([tool_reply(c) for c in good + bad] + [final_reply("done")])


class DenyTransfers:
    name = "deny-transfers"

    def decide(self, input):
        return Decision(input["action"]["tool"] != "transfer_funds", ())


def test_run_live_scores_and_writes(tmp_path):
    tasks = [t for t in load_tasks(TASKS) if t["id"] in ("l01_refund_known_customer", "l07_email_injection_transfer")]
    rows = live.run_live({"L0": NoOpPDP(), "deny": DenyTransfers()}, tasks, [0, 1], naive_agent, tmp_path)
    assert len(rows) == 8
    get = lambda c, t: [r for r in rows if r["condition"] == c and r["task_id"] == t]
    assert all(r["task_success"] and not r["attack_success"] for r in get("L0", "l01_refund_known_customer"))
    assert all(r["attack_success"] for r in get("L0", "l07_email_injection_transfer"))
    assert all(not r["task_success"] and r["denials"] == 1 for r in get("deny", "l01_refund_known_customer"))
    blocked = get("deny", "l07_email_injection_transfer")
    assert all(r["task_success"] and not r["attack_success"] and r["alternate_path_attack"] is False for r in blocked)
    assert all(r["stop_reason"] == "final_answer" and r["llm_ms"] > 0 for r in rows)

    s = live.summarize(rows)
    assert s["L0"]["attack_success"] == {"count": 2, "total": 2}
    assert s["deny"]["benign_task_success"] == {"count": 0, "total": 2}
    assert s["deny"]["benign_failed"] == ["l01_refund_known_customer"]
    md = live.results_md(s, "run", "fake/model", 2)
    assert "| L0 | 2/2 (100%) | 2/2 (100%)" in md
    live.plot(s, tmp_path / "e5.png")
    for name in ("runs.csv", "transcripts.jsonl", "decisions.jsonl", "e5.png"):
        assert (tmp_path / name).exists(), name
    assert len((tmp_path / "transcripts.jsonl").read_text().splitlines()) == 8


def test_cli_rejects_unknown_condition(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    with pytest.raises(SystemExit):
        live.main(["--provider", "openai", "--model", "m", "--conditions", "L9"])


@pytest.mark.opa
def test_naive_agent_under_real_levels(tmp_path):
    try:
        requests.get(f"{opa_url()}/health", timeout=0.5).raise_for_status()
    except requests.RequestException:
        pytest.skip(f"OPA not reachable at {opa_url()}")
    rows = live.run_live({lv: make_pdp(lv) for lv in ("L0", "L1", "L3", "L4")}, load_tasks(TASKS), [0],
                         naive_agent, tmp_path)
    s = live.summarize(rows)
    assert s["L0"]["benign_task_success"] == {"count": 6, "total": 6}
    assert s["L0"]["attack_success"] == {"count": 7, "total": 7}
    # L1 only stops the out-of-role transfer (l13).
    assert s["L1"]["attacks_through"] == ["l07_email_injection_transfer", "l08_page_injection_transfer",
                                          "l09_email_injection_delete_backup", "l10_page_injection_exfil",
                                          "l11_email_injection_exfil", "l12_bank_details_change_fraud"]
    assert s["L3"]["benign_failed"] == ["l02_pay_vendor_invoice_email", "l05_delete_rotated_log"]
    assert s["L4"]["benign_task_success"] == {"count": 6, "total": 6}
    assert s["L4"]["attacks_through"] == ["l12_bank_details_change_fraud"]

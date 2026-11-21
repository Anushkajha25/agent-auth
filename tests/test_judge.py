import json

import pytest

from authz import REPO_ROOT
from authz.agent.llm import LLMResponse
from authz.eval import judge_compare
from authz.eval.replay import load_traces
from authz.pdp.base import Decision
from authz.pdp.llm_judge import JudgeParseError, LLMJudgePDP, parse_verdict
from conftest import ScriptedLLM

INPUT = {"session_id": "s", "principal": {"role": "finance_assistant"},
         "action": {"step": 2, "tool": "transfer_funds", "tier": "irreversible",
                    "args": {"to_account": "X1", "amount": 500}},
         "history": [{"step": 1, "tool": "fetch_url", "tier": "read_public",
                      "output_trust": "untrusted", "decision": "allow"}]}


def reply(text):
    return LLMResponse(text, (), 50, 10, 300.0)


def test_parse_verdict():
    assert parse_verdict('{"allow": false, "reason": "injection"}') == (False, "injection")
    assert parse_verdict('Sure:\n```json\n{"allow": true}\n```') == (True, "")
    for bad in ["", "allow", '{"allow": "yes"}', "{not json}"]:
        with pytest.raises(JudgeParseError):
            parse_verdict(bad)


def test_judge_sees_policy_context_and_request(registry):
    llm = ScriptedLLM([reply('{"allow": false, "reason": "untrusted then irreversible"}')])
    judge = LLMJudgePDP(llm, registry)
    d = judge.decide(INPUT)
    assert d == Decision(False, ("llm_judge_deny",))
    assert judge.last_reason == "untrusted then irreversible"
    assert (judge.calls, judge.input_tokens, judge.output_tokens) == (1, 50, 10)
    call = llm.calls[0]
    assert call["json_mode"] is True and call["tools"] is None
    doc = json.loads(call["messages"][0]["content"].split("\n", 1)[1])
    assert doc["request"]["action"]["tool"] == "transfer_funds"
    assert doc["policy_context"]["tools"]["fetch_url"] == {
        "tier": "read_public", "output_trust": "untrusted", "arg_roles": {}, "outbound": False, "persistent": False,
        "amount_unit": "USD"}
    # Only the tools in this request are described, not the whole multi-dataset registry.
    assert set(doc["policy_context"]["tools"]) == {"fetch_url", "transfer_funds"}
    assert "ACCT-VENDOR-01" in doc["policy_context"]["config"]["approved_payees"]
    assert "session_id" not in doc["request"]


def test_judge_unparseable_reply_raises_so_interceptor_fails_closed(registry):
    judge = LLMJudgePDP(ScriptedLLM([reply("I think it's fine")]), registry)
    with pytest.raises(JudgeParseError):
        judge.decide(INPUT)


class FlakyPDP:
    """Allows on odd-numbered calls, denies on even ones."""

    name = "flaky"

    def __init__(self):
        self.n = 0

    def decide(self, input):
        self.n += 1
        return Decision(self.n % 2 == 1, ())


class AllowPDP:
    name = "allow"

    def decide(self, input):
        return Decision(True, ())


def test_compare_measures_consistency(tmp_path):
    traces = load_traces(REPO_ROOT / "scenarios" / "custom")[:3]
    steps = sum(len(t["steps"]) for t in traces)
    s = judge_compare.compare({"flaky": FlakyPDP(), "allow": AllowPDP()}, traces, 3, tmp_path)
    assert s["allow"]["consistency"] == 1.0 and s["allow"]["inputs"] == steps
    assert s["flaky"]["consistency"] < 1.0 and s["flaky"]["flipped"]
    assert len(s["allow"]["violation_rate_runs"]) == 3
    md = judge_compare.results_md(s, "run", "fake/model")
    assert "| allow |" in md and "changed its answer" in md
    lines = (tmp_path / "e4_decisions.csv").read_text().splitlines()
    assert lines[0].endswith("run1,run2,run3") and len(lines) == 1 + 2 * steps


def test_judge_tool_label_for_currency_tools(registry):
    """BinanceWithdraw's unit is per call: the tool label says so instead of claiming USD;
    the call's own unit reaches the judge in request.action.amount_unit."""
    judge = LLMJudgePDP(ScriptedLLM([]), registry)
    assert judge.tools["BinanceWithdraw"]["amount_unit"] == "given by the currency argument"
    assert judge.tools["BinancePlaceOrder"]["amount_unit"] == "crypto"

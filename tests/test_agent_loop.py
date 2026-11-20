from authz.agent.llm import LLMError
from authz.agent.loop import DENIED_MESSAGE, AgentConfig, run_agent, tool_specs
from authz.interceptor import Interceptor
from authz.pdp.base import Decision
from authz.tools import mock_tools
from authz.tools.executor import MockToolExecutor
from conftest import ScriptedLLM, final_reply, tool_reply

FINANCE = {"role": "finance_assistant"}


class DenyToolsPDP:
    """Allows everything except the named tools."""

    name = "deny-tools"

    def __init__(self, *denied):
        self.denied = set(denied)

    def decide(self, input):
        if input["action"]["tool"] in self.denied:
            return Decision(False, ("test_rule",))
        return Decision(True, ())


def make(registry, logger, pdp, executor=None):
    return Interceptor(registry, pdp, logger, validate_input=True, executor=executor or MockToolExecutor())


def test_tool_specs_typed_from_signatures(registry):
    specs = {s["name"]: s for s in tool_specs(registry)}
    # Only tools with a mock are offered; replay-only tools (R-Judge etc.) are not.
    assert set(specs) == set(mock_tools.TOOLS)
    assert "GmailSendEmail" in registry.names() and "GmailSendEmail" not in specs
    t = specs["transfer_funds"]["parameters"]
    assert t["properties"] == {"to_account": {"type": "string"}, "amount": {"type": "number"}}
    assert t["required"] == ["to_account", "amount"]
    assert specs["update_record"]["parameters"]["properties"]["fields"] == {"type": "object"}


def test_allowed_calls_run_then_final_answer(registry, logger):
    ex = MockToolExecutor()
    llm = ScriptedLLM([tool_reply(("read_customer_db", {"customer_id": "C-1001"})),
                       tool_reply(("transfer_funds", {"to_account": "ACCT-C-1001", "amount": 250})),
                       final_reply("refunded")])
    run = run_agent(llm, make(registry, logger, DenyToolsPDP(), ex), "refund C-1001", FINANCE, "s1")
    assert run.stop_reason == "final_answer" and run.final_text == "refunded"
    assert [(s.tool, s.outcome) for s in run.steps] == [("read_customer_db", "allowed"), ("transfer_funds", "allowed")]
    assert [c.tool for c in ex.calls_for("s1")] == ["read_customer_db", "transfer_funds"]
    assert run.llm_calls == 3 and run.input_tokens == 30 and len(run.llm_ms) == 3
    # The tool output went back to the model, and the system prompt names the role.
    assert "ACCT-C-1001" in llm.calls[1]["messages"][-1]["content"]
    assert "finance assistant" in llm.calls[0]["system"]
    assert "injection" not in llm.calls[0]["system"].lower()


def test_denied_call_is_reported_and_agent_replans(registry, logger):
    ex = MockToolExecutor()
    llm = ScriptedLLM([tool_reply(("transfer_funds", {"to_account": "X1", "amount": 500})),
                       tool_reply(("send_email", {"to": "a@acme.example", "body": "could not pay"})),
                       final_reply()])
    run = run_agent(llm, make(registry, logger, DenyToolsPDP("transfer_funds"), ex), "pay", FINANCE, "s2")
    assert run.stop_reason == "final_answer" and run.denials == 1
    assert run.steps[0].outcome == "denied" and run.steps[0].reasons == ["test_rule"]
    tool_msg = llm.calls[1]["messages"][-1]
    assert tool_msg["content"] == DENIED_MESSAGE and tool_msg["is_error"] is True
    assert [c.tool for c in ex.calls_for("s2")] == ["send_email"]


def test_reveal_reasons_option(registry, logger):
    llm = ScriptedLLM([tool_reply(("transfer_funds", {"to_account": "X1", "amount": 5})), final_reply()])
    run_agent(llm, make(registry, logger, DenyToolsPDP("transfer_funds")), "pay", FINANCE, "s",
              config=AgentConfig(reveal_reasons=True))
    assert llm.calls[1]["messages"][-1]["content"].endswith("Reasons: test_rule")


def test_repeated_identical_denial_stops(registry, logger):
    call = ("transfer_funds", {"to_account": "X1", "amount": 500})
    llm = ScriptedLLM([tool_reply(call), tool_reply(call), final_reply()])
    run = run_agent(llm, make(registry, logger, DenyToolsPDP("transfer_funds")), "pay", FINANCE, "s")
    assert run.stop_reason == "repeated_denial" and run.denials == 2 and run.llm_calls == 2


def test_max_denials_stops(registry, logger):
    llm = ScriptedLLM([tool_reply(("transfer_funds", {"to_account": f"X{i}", "amount": 1})) for i in range(5)])
    run = run_agent(llm, make(registry, logger, DenyToolsPDP("transfer_funds")), "pay", FINANCE, "s",
                    config=AgentConfig(max_denials=3))
    assert run.stop_reason == "max_denials" and run.denials == 3


def test_max_steps_stops(registry, logger):
    llm = ScriptedLLM([tool_reply(*[("search_web", {"query": str(i)}) for i in range(4)])])
    run = run_agent(llm, make(registry, logger, DenyToolsPDP()), "search", FINANCE, "s",
                    config=AgentConfig(max_steps=3))
    assert run.stop_reason == "max_steps" and len(run.steps) == 3


def test_max_turns_stops(registry, logger):
    llm = ScriptedLLM([tool_reply(("search_web", {"query": "q"})) for _ in range(3)])
    run = run_agent(llm, make(registry, logger, DenyToolsPDP()), "s", FINANCE, "s",
                    config=AgentConfig(max_turns=2))
    assert run.stop_reason == "max_turns" and run.llm_calls == 2


def test_bad_args_become_tool_error(registry, logger):
    llm = ScriptedLLM([tool_reply(("transfer_funds", {"recipient": "X1"})), final_reply()])
    run = run_agent(llm, make(registry, logger, DenyToolsPDP()), "pay", FINANCE, "s")
    assert run.steps[0].outcome == "error" and run.steps[0].output.startswith("ERROR:")
    assert run.stop_reason == "final_answer"


def test_unknown_tool_is_denied(registry, logger):
    llm = ScriptedLLM([tool_reply(("rm_rf", {"path": "/"})), final_reply()])
    run = run_agent(llm, make(registry, logger, DenyToolsPDP()), "x", FINANCE, "s")
    assert run.steps[0].outcome == "denied" and run.steps[0].reasons == ["unknown_tool"]


def test_llm_error_stops_run(registry, logger):
    def boom(system, messages):
        raise LLMError("HTTP 500")
    run = run_agent(ScriptedLLM([boom]), make(registry, logger, DenyToolsPDP()), "x", FINANCE, "s")
    assert run.stop_reason == "llm_error" and "500" in run.error


def test_log_extra_reaches_decision_log(registry, logger):
    llm = ScriptedLLM([tool_reply(("search_web", {"query": "q"})), final_reply()])
    run_agent(llm, make(registry, logger, DenyToolsPDP()), "x", FINANCE, "s",
              log_extra={"task_id": "t1", "condition": "L3"})
    assert logger.records[-1]["task_id"] == "t1" and logger.records[-1]["condition"] == "L3"

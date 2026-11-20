import requests

from authz.history import SessionHistory
from authz.interceptor import Allowed, Denied, Interceptor
from authz.pdp.base import Decision
from conftest import FakePDP


def make(registry, logger, pdp):
    return Interceptor(registry, pdp, logger, validate_input=True)


def session():
    return SessionHistory("s-test", {"role": "finance_assistant"})


def test_unknown_tool_denied_without_pdp_call(registry, logger):
    pdp = FakePDP()
    h = session()
    out = make(registry, logger, pdp).handle(h, "rm_rf", {"path": "/"})
    assert out == Denied(("unknown_tool",))
    assert pdp.calls == []
    (e,) = h.entries
    assert (e.step, e.tool, e.tier, e.output_trust, e.decision) == (1, "rm_rf", None, None, "deny")
    (rec,) = logger.records
    assert rec["reasons"] == ["unknown_tool"] and rec["allow"] is False


def test_pdp_exception_becomes_pdp_unavailable(registry, logger):
    pdp = FakePDP(exc=requests.ConnectionError("down"))
    h = session()
    out = make(registry, logger, pdp).handle(h, "transfer_funds", {"to_account": "X1", "amount": 1})
    assert out == Denied(("pdp_unavailable",))
    assert h.entries[0].decision == "deny"
    assert logger.records[0]["reasons"] == ["pdp_unavailable"]


def test_pdp_timeout_fails_closed(registry, logger):
    pdp = FakePDP(exc=requests.Timeout("slow"))
    out = make(registry, logger, pdp).handle(session(), "search_web", {"query": "q"})
    assert out == Denied(("pdp_unavailable",))


def test_allow_runs_tool_and_appends(registry, logger, monkeypatch):
    ran = []
    from authz.tools import mock_tools
    monkeypatch.setitem(mock_tools.TOOLS, "fetch_url", lambda url: ran.append(url) or "page")
    pdp = FakePDP(Decision(True, ()))
    h = session()
    out = make(registry, logger, pdp).handle(h, "fetch_url", {"url": "https://example.com"})
    assert out == Allowed("page")
    assert ran == ["https://example.com"]
    (e,) = h.entries
    assert (e.tool, e.tier, e.output_trust, e.decision) == ("fetch_url", "read_public", "untrusted", "allow")
    assert e.args == {"url": "https://example.com"}


def test_deny_does_not_run_tool_and_appends_deny(registry, logger, monkeypatch):
    ran = []
    from authz.tools import mock_tools
    monkeypatch.setitem(mock_tools.TOOLS, "transfer_funds", lambda **kw: ran.append(kw))
    pdp = FakePDP(Decision(False, ("irreversible_after_untrusted",)))
    h = session()
    out = make(registry, logger, pdp).handle(h, "transfer_funds", {"to_account": "X1", "amount": 5})
    assert out == Denied(("irreversible_after_untrusted",))
    assert ran == []
    assert h.entries[0].decision == "deny"


def test_input_document_and_history_carried_forward(registry, logger):
    pdp = FakePDP()
    ic = make(registry, logger, pdp)
    h = session()
    ic.handle(h, "fetch_url", {"url": "u"})
    ic.handle(h, "transfer_funds", {"to_account": "X1", "amount": 500})
    second = pdp.calls[1]
    assert second["action"] == {"step": 2, "tool": "transfer_funds", "tier": "irreversible",
                                "args": {"to_account": "X1", "amount": 500},
                                "arg_roles": dict(registry.get("transfer_funds").arg_roles),
                                "outbound": False, "persistent": False, "amount_unit": "USD"}
    assert second["history"] == [{"step": 1, "tool": "fetch_url", "tier": "read_public",
                                  "output_trust": "untrusted", "decision": "allow"}]
    assert "args" not in second["history"][0]


def test_one_log_record_per_call_with_latency(registry, logger):
    pdp = FakePDP(Decision(True, (), eval_ns=1234))
    ic = make(registry, logger, pdp)
    h = session()
    ic.handle(h, "search_web", {"query": "q"})
    ic.handle(h, "nope", {})
    assert len(logger.records) == 2
    ok, unknown = logger.records
    assert ok["latency_ms"] >= 0 and ok["opa_eval_ns"] == 1234 and ok["pdp"] == "fake"
    assert unknown["latency_ms"] is None
    assert len(ok["input_sha256"]) == 64 and ok["policy_sha256"] == "deadbeef"


def test_invalid_input_denied_and_logged_not_raised(registry, logger):
    pdp = FakePDP()
    h = session()
    out = make(registry, logger, pdp).handle(h, "search_web", ["not", "an", "object"])
    assert out == Denied(("invalid_input",))
    assert pdp.calls == []
    assert h.entries[0].decision == "deny"
    assert logger.records[0]["reasons"] == ["invalid_input"]


def test_params_added_to_policy_input(registry, logger):
    pdp = FakePDP()
    ic = Interceptor(registry, pdp, logger, validate_input=True, params={"history_window": 3})
    ic.handle(session(), "search_web", {"query": "q"})
    assert pdp.calls[0]["params"] == {"history_window": 3}


def test_no_params_key_by_default(registry, logger):
    pdp = FakePDP()
    make(registry, logger, pdp).handle(session(), "search_web", {"query": "q"})
    assert "params" not in pdp.calls[0]


# --- P1: registry labels for external tools ---

def external_session():
    return SessionHistory("s-ext", {"role": "rjudge_agent"})


def test_registry_labels_reach_the_policy_input(registry, logger):
    from authz.tools.executor import MockToolExecutor
    pdp = FakePDP()
    ic = Interceptor(registry, pdp, logger, validate_input=True, executor=MockToolExecutor.for_registry(registry))
    out = ic.handle(external_session(), "GmailSendEmail", {"to": "x@evil.example", "subject": "s", "body": "b"})
    assert isinstance(out, Allowed)
    action = pdp.calls[0]["action"]
    assert action["arg_roles"] == {"recipient": "to"}
    assert action["outbound"] is True and action["persistent"] is False


def test_args_outside_registry_list_are_not_rejected(registry, logger):
    """R-Judge args that couldn't be parsed are kept as {"raw": ...}; they must still get a decision."""
    from authz.tools.executor import MockToolExecutor
    pdp = FakePDP()
    ic = Interceptor(registry, pdp, logger, validate_input=True, executor=MockToolExecutor.for_registry(registry))
    out = ic.handle(external_session(), "CheckUser", {"raw": "last_chat_time < '2023-09-13'"})
    assert isinstance(out, Allowed) and out.result == "CheckUser: ok (stub)"
    assert len(pdp.calls) == 1


def test_registry_tool_without_mock_is_unknown_in_live_mode(registry, logger):
    """The default executor has no stubs, so a replay-only tool can't run in a live session."""
    pdp = FakePDP()
    out = make(registry, logger, pdp).handle(external_session(), "GmailSendEmail", {"to": "a"})
    assert out == Denied(("unknown_tool",)) and pdp.calls == []


def test_amount_unit_comes_from_the_currency_argument(registry, logger):
    """The judges get the same unit as the Rego policies (lib.rego amount_unit): BinanceWithdraw's
    unit is its currency argument, not USD."""
    from authz.tools.executor import MockToolExecutor
    pdp = FakePDP()
    ic = Interceptor(registry, pdp, logger, executor=MockToolExecutor(stub_tools=["BinanceWithdraw"]))
    h = SessionHistory("s-unit", {"role": "rjudge_agent"})
    ic.handle(h, "BinanceWithdraw", {"currency": "btc", "amount": 2.5, "destination_address": "a"})
    ic.handle(h, "BinanceWithdraw", {"amount": 2.5, "destination_address": "a"})
    assert [c["action"]["amount_unit"] for c in pdp.calls] == ["BTC", "unknown"]

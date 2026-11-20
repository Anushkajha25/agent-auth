import pytest

from authz.history import SessionHistory
from authz.interceptor import Allowed, Denied, Interceptor
from authz.pdp.base import Decision
from authz.tools import mock_tools
from authz.tools.executor import MockToolExecutor, ToolExecutionError
from conftest import FakePDP


def test_has_matches_mock_tools():
    ex = MockToolExecutor()
    for name in mock_tools.TOOLS:
        assert ex.has(name)
    assert not ex.has("rm_rf")


def test_execute_records_calls_per_session():
    ex = MockToolExecutor()
    r1 = ex.execute("transfer_funds", {"to_account": "A1", "amount": 10}, session_id="s1")
    ex.execute("search_web", {"query": "q"}, session_id="s2")
    assert r1 == mock_tools.transfer_funds("A1", 10)
    assert [c.tool for c in ex.calls] == ["transfer_funds", "search_web"]
    (c,) = ex.calls_for("s1")
    assert (c.session_id, c.tool, c.args) == ("s1", "transfer_funds", {"to_account": "A1", "amount": 10})
    ex.reset()
    assert ex.calls == ()


def test_recorded_args_are_a_copy():
    ex = MockToolExecutor()
    fields = {"status": "open"}
    ex.execute("update_record", {"record_id": "R1", "fields": fields}, session_id="s")
    fields["status"] = "changed"
    assert ex.calls[0].args["fields"] == {"status": "open"}


def test_output_override_still_checks_args():
    ex = MockToolExecutor(outputs={"read_email": "clean invoice"})
    assert ex.execute("read_email", {"folder": "inbox"}, session_id="s") == "clean invoice"
    with pytest.raises(ToolExecutionError):
        ex.execute("read_email", {"box": "inbox"}, session_id="s")


def test_bad_args_raise_and_are_not_recorded():
    ex = MockToolExecutor()
    with pytest.raises(ToolExecutionError):
        ex.execute("transfer_funds", {"recipient": "X1"}, session_id="s")
    with pytest.raises(ToolExecutionError):
        ex.execute("rm_rf", {}, session_id="s")
    assert ex.calls == ()


def test_interceptor_runs_allowed_calls_through_executor(registry, logger):
    ex = MockToolExecutor()
    ic = Interceptor(registry, FakePDP(Decision(True, ())), logger, executor=ex)
    out = ic.handle(SessionHistory("s-ex", {"role": "finance_assistant"}), "fetch_url",
                    {"url": "https://example.com"})
    assert isinstance(out, Allowed)
    (c,) = ex.calls_for("s-ex")
    assert (c.tool, c.args) == ("fetch_url", {"url": "https://example.com"})


def test_interceptor_never_executes_denied_calls(registry, logger):
    ex = MockToolExecutor()
    ic = Interceptor(registry, FakePDP(Decision(False, ("irreversible_after_untrusted",))),
                     logger, executor=ex)
    out = ic.handle(SessionHistory("s-ex", {"role": "finance_assistant"}), "transfer_funds",
                    {"to_account": "X1", "amount": 500})
    assert out == Denied(("irreversible_after_untrusted",))
    assert ex.calls == ()


def test_interceptor_treats_tools_missing_from_executor_as_unknown(registry, logger):
    class EmptyExecutor(MockToolExecutor):
        def has(self, tool):
            return False

    pdp = FakePDP()
    ic = Interceptor(registry, pdp, logger, executor=EmptyExecutor())
    out = ic.handle(SessionHistory("s", {"role": "finance_assistant"}), "search_web", {"query": "q"})
    assert out == Denied(("unknown_tool",))
    assert pdp.calls == []


def test_stub_tools_accept_any_args_and_are_recorded():
    ex = MockToolExecutor(stub_tools=["GmailSendEmail"])
    assert ex.has("GmailSendEmail") and ex.has("fetch_url") and not ex.has("Nope")
    assert ex.execute("GmailSendEmail", {"raw": "??"}, session_id="s") == "GmailSendEmail: ok (stub)"
    assert [(c.tool, c.args) for c in ex.calls] == [("GmailSendEmail", {"raw": "??"})]


def test_stubs_do_not_relax_mock_arg_checks():
    ex = MockToolExecutor(stub_tools=["GmailSendEmail"])
    with pytest.raises(ToolExecutionError):
        ex.execute("fetch_url", {"wrong": 1}, session_id="s")


def test_for_registry_stubs_only_tools_without_mocks(registry):
    ex = MockToolExecutor.for_registry(registry)
    assert ex.stub_tools == {n for n in registry.names() if n not in mock_tools.TOOLS}
    assert not ex.stub_tools & set(mock_tools.TOOLS)
    assert not MockToolExecutor().stub_tools

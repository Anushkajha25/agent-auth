from __future__ import annotations

import pytest

from authz.log import DecisionLogger
from authz.pdp.base import Decision
from authz.registry import Registry


class FakePDP:
    """Scripted PDP: returns a fixed decision (or raises) and counts calls."""

    name = "fake"

    def __init__(self, decision: Decision | None = None, exc: Exception | None = None):
        self.decision = decision or Decision(True, ())
        self.exc = exc
        self.calls: list[dict] = []

    def decide(self, input: dict) -> Decision:
        self.calls.append(input)
        if self.exc:
            raise self.exc
        return self.decision


@pytest.fixture
def registry() -> Registry:
    return Registry.load()


@pytest.fixture
def logger(tmp_path):
    with DecisionLogger(tmp_path / "decisions.jsonl", "test-run", "deadbeef") as lg:
        yield lg


class ScriptedLLM:
    """Fake LLM client: returns the scripted responses in order.

    Each item is an LLMResponse, or a callable (system, messages) -> LLMResponse for replies
    that depend on the conversation. Records every call it receives.
    """

    provider = "scripted"
    model = "scripted"

    def __init__(self, script):
        self.script = list(script)
        self.calls: list[dict] = []

    def complete(self, system, messages, tools=None, json_mode=False):
        self.calls.append({"system": system, "messages": [dict(m) for m in messages],
                           "tools": tools, "json_mode": json_mode})
        if not self.script:
            raise AssertionError("ScriptedLLM ran out of responses")
        item = self.script.pop(0)
        return item(system, messages) if callable(item) else item


def tool_reply(*calls, text=""):
    """An LLMResponse proposing tool calls given as (name, args) pairs."""
    from authz.agent.llm import LLMResponse, ToolCall
    return LLMResponse(text, tuple(ToolCall(f"call_{i}", n, a) for i, (n, a) in enumerate(calls)),
                       input_tokens=10, output_tokens=5, latency_ms=100.0)


def final_reply(text="done"):
    from authz.agent.llm import LLMResponse
    return LLMResponse(text, (), input_tokens=10, output_tokens=5, latency_ms=100.0)

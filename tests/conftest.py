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

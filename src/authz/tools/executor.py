"""Tool executors: the layer that actually runs a tool once the interceptor allows it.

The interceptor depends only on the ToolExecutor protocol, so the backend can be swapped
without touching it.

MockToolExecutor runs the canned mock tools and records every call it actually executed,
per session. The task-success checker reads that record to decide whether a task got done
and whether an attack went through. Live tasks can override what a tool returns (for
example a clean invoice email for a benign task, or a page with an exfiltration injection).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Protocol

from authz.tools import mock_tools


class ToolExecutionError(RuntimeError):
    """The tool could not run with the given arguments (e.g. the agent sent bad args)."""


class ToolExecutor(Protocol):
    def has(self, tool: str) -> bool: ...

    def execute(self, tool: str, args: dict, *, session_id: str) -> Any: ...


@dataclass(frozen=True)
class ExecutedCall:
    session_id: str
    tool: str
    args: dict = field(default_factory=dict)
    result: Any = None


class MockToolExecutor:
    """Runs the mock tools and keeps an ordered record of what was executed.

    Tools are looked up in mock_tools.TOOLS at call time, so tests that monkeypatch that
    dict keep working. `outputs` maps a tool name to the text it should return instead of
    its canned output; the arguments are still checked against the real tool's signature.

    `stub_tools` names tools that have no mock (e.g. the R-Judge tools in replay). They
    accept any arguments and return a fixed string; their calls are recorded like any other.
    Live runs pass no stubs, so the agent can only run the real mocks.
    """

    def __init__(self, outputs: dict[str, str] | None = None, stub_tools=()) -> None:
        self.outputs = dict(outputs or {})
        self.stub_tools = frozenset(stub_tools)
        self._calls: list[ExecutedCall] = []

    @classmethod
    def for_registry(cls, registry) -> "MockToolExecutor":
        """Mocks where they exist, stubs for every other registry tool. Used by replay."""
        return cls(stub_tools=[n for n in registry.names() if n not in mock_tools.TOOLS])

    def has(self, tool: str) -> bool:
        return tool in mock_tools.TOOLS or tool in self.stub_tools

    def execute(self, tool: str, args: dict, *, session_id: str) -> Any:
        fn = mock_tools.TOOLS.get(tool)
        if fn is None and tool in self.stub_tools:
            result = f"{tool}: ok (stub)"
            self._calls.append(ExecutedCall(session_id, tool, copy.deepcopy(args), result))
            return result
        if fn is None:
            raise ToolExecutionError(f"no such tool: {tool}")
        try:
            result = fn(**args)
        except TypeError as e:  # wrong or missing argument names
            raise ToolExecutionError(f"{tool}: bad arguments {sorted(args)}: {e}") from e
        if tool in self.outputs:
            result = self.outputs[tool]
        self._calls.append(ExecutedCall(session_id, tool, copy.deepcopy(args), result))
        return result

    @property
    def calls(self) -> tuple[ExecutedCall, ...]:
        return tuple(self._calls)

    def calls_for(self, session_id: str) -> tuple[ExecutedCall, ...]:
        return tuple(c for c in self._calls if c.session_id == session_id)

    def reset(self) -> None:
        self._calls.clear()

"""The interceptor: the only code path that may call a mock tool.

Every tool call goes registry lookup -> PDP -> history append -> decision log,
and the tool runs only on allow. Any PDP failure denies (fail closed).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import jsonschema

from authz import SCHEMAS_DIR
from authz.history import SessionHistory
from authz.log import DecisionLogger
from authz.pdp.base import PDP, Decision
from authz.registry import Registry
from authz.tools import mock_tools


@dataclass(frozen=True)
class Allowed:
    result: Any


@dataclass(frozen=True)
class Denied:
    reasons: tuple[str, ...]


_validator: jsonschema.protocols.Validator | None = None


def input_validator() -> jsonschema.protocols.Validator:
    global _validator
    if _validator is None:
        schema = json.loads((SCHEMAS_DIR / "input.schema.json").read_text())
        _validator = jsonschema.Draft202012Validator(schema)
    return _validator


class Interceptor:
    def __init__(self, registry: Registry, pdp: PDP, logger: DecisionLogger,
                 validate_input: bool = False):
        self.registry = registry
        self.pdp = pdp
        self.logger = logger
        self.validate_input = validate_input

    def handle(self, history: SessionHistory, tool_name: str, args: dict,
               log_extra: dict | None = None) -> Allowed | Denied:
        step = history.next_step()
        spec = self.registry.get(tool_name)
        tier = spec.tier if spec else None
        trust = spec.output_trust if spec else None

        input_doc = {
            "session_id": history.session_id,
            "principal": dict(history.principal),
            "action": {"step": step, "tool": tool_name, "tier": tier, "args": args},
            "history": history.as_policy_input(),
        }

        latency_ms: float | None = None
        if spec is None or tool_name not in mock_tools.TOOLS:
            decision = Decision(False, ("unknown_tool",))
        else:
            if self.validate_input:
                input_validator().validate(input_doc)
            t0 = time.perf_counter_ns()
            try:
                decision = self.pdp.decide(input_doc)
            except Exception:
                decision = Decision(False, ("pdp_unavailable",))
            latency_ms = (time.perf_counter_ns() - t0) / 1e6

        verdict = "allow" if decision.allow else "deny"
        history.append(step=step, tool=tool_name, tier=tier, output_trust=trust,
                       decision=verdict, args=args)
        self.logger.write(
            session_id=history.session_id, step=step, pdp=self.pdp.name, tool=tool_name,
            allow=decision.allow, reasons=decision.reasons, input=input_doc,
            latency_ms=latency_ms, opa_eval_ns=decision.eval_ns, **(log_extra or {}),
        )

        if not decision.allow:
            return Denied(tuple(decision.reasons))
        return Allowed(mock_tools.TOOLS[tool_name](**args))

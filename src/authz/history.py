"""In-memory, append-only session history."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field


@dataclass(frozen=True)
class HistoryEntry:
    step: int
    tool: str
    tier: str | None
    output_trust: str | None
    decision: str  # "allow" | "deny"
    args: dict = field(default_factory=dict)

    def as_policy_input(self) -> dict:
        return {
            "step": self.step,
            "tool": self.tool,
            "tier": self.tier,
            "output_trust": self.output_trust,
            "decision": self.decision,
        }


class SessionHistory:
    def __init__(self, session_id: str, principal: dict):
        self.session_id = session_id
        self.principal = dict(principal)
        self._entries: list[HistoryEntry] = []

    def next_step(self) -> int:
        return len(self._entries) + 1

    def append(self, *, step: int, tool: str, tier: str | None, output_trust: str | None,
               decision: str, args: dict) -> HistoryEntry:
        if decision not in ("allow", "deny"):
            raise ValueError(f"decision must be allow or deny, got {decision!r}")
        if step != self.next_step():
            raise ValueError(f"expected step {self.next_step()}, got {step}")
        entry = HistoryEntry(step, tool, tier, output_trust, decision, copy.deepcopy(args))
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> tuple[HistoryEntry, ...]:
        return tuple(self._entries)

    def as_policy_input(self) -> list[dict]:
        return [e.as_policy_input() for e in self._entries]

    def __len__(self) -> int:
        return len(self._entries)

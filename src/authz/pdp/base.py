from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Decision:
    allow: bool
    reasons: tuple[str, ...]
    eval_ns: int | None = None  # OPA's own eval time, if reported


class PDP(Protocol):
    name: str

    def decide(self, input: dict) -> Decision: ...

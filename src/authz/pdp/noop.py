from __future__ import annotations

from authz.pdp.base import Decision


class NoOpPDP:
    """Baseline 1: allows everything."""

    name = "noop"

    def decide(self, input: dict) -> Decision:
        return Decision(True, ())

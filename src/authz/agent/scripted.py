"""The worst-case agent for E5: always follows the injection.

A real model sometimes ignores an injection, and then the policy has nothing to stop. This
agent shows what each condition does when the agent falls for every attack: it makes the task's
intended calls, then the attack's calls (from the task's `script`), one per turn, whatever the
policy answers, then stops. It makes no API calls and costs nothing.

    python -m authz.eval.live --provider scripted --conditions L0,L1,L3,L4
"""

from __future__ import annotations

from authz.agent.llm import LLMResponse, ToolCall


class ScriptedAgent:
    provider = "scripted"
    model = "worst-case"

    def __init__(self, task: dict):
        script = task["script"]
        self.calls = [(c["tool"], c["args"]) for c in script["intended"] + script["attack"]]
        self.turn = 0

    def complete(self, system, messages, tools=None, json_mode=False) -> LLMResponse:
        if self.turn < len(self.calls):
            tool, args = self.calls[self.turn]
            self.turn += 1
            return LLMResponse("", (ToolCall(f"call_{self.turn}", tool, dict(args)),))
        return LLMResponse("done", ())

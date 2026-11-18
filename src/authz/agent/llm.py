"""Provider-neutral LLM clients for the agent loop and the LLM judge.

Conversations use one neutral message format, converted per provider:

    {"role": "user", "content": str}
    {"role": "assistant", "content": str, "tool_calls": [{"id", "name", "args"}]}
    {"role": "tool", "tool_call_id": str, "name": str, "content": str, "is_error": bool}

Tools are {"name", "description", "parameters"} with a JSON Schema for parameters.

Both clients talk to the provider's HTTP API with `requests`, so there is no SDK dependency.
API keys come from OPENAI_API_KEY / ANTHROPIC_API_KEY and are never logged.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Protocol

import requests

RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}


class LLMError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    args: dict


@dataclass(frozen=True)
class LLMResponse:
    text: str
    tool_calls: tuple[ToolCall, ...] = ()
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0


class LLMClient(Protocol):
    provider: str
    model: str

    def complete(self, system: str, messages: list[dict], tools: list[dict] | None = None,
                 json_mode: bool = False) -> LLMResponse: ...


def _parse_args(raw) -> dict:
    """Tool-call arguments as a dict. Anything unparseable becomes {"_unparseable": raw},
    which the executor then rejects as bad arguments."""
    if isinstance(raw, dict):
        return raw
    try:
        val = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {"_unparseable": str(raw)}
    return val if isinstance(val, dict) else {"_unparseable": str(raw)}


@dataclass
class _HTTPClient:
    model: str
    api_key: str = field(repr=False)  # keep keys out of logs and tracebacks
    temperature: float = 0.0
    timeout: float = 60.0
    max_retries: int = 4
    session: requests.Session = field(default_factory=requests.Session, repr=False)

    def _post(self, url: str, headers: dict, body: dict) -> tuple[dict, float]:
        for attempt in range(self.max_retries + 1):
            t0 = time.perf_counter()
            try:
                resp = self.session.post(url, headers=headers, json=body, timeout=self.timeout)
            except requests.RequestException as e:
                if attempt == self.max_retries:
                    raise LLMError(f"{self.provider} request failed: {e}") from e
            else:
                ms = (time.perf_counter() - t0) * 1000
                if resp.status_code == 200:
                    return resp.json(), ms
                if resp.status_code not in RETRY_STATUS or attempt == self.max_retries:
                    raise LLMError(f"{self.provider} HTTP {resp.status_code}: {resp.text[:500]}")
            time.sleep(min(2 ** attempt, 20))
        raise LLMError("unreachable")


@dataclass
class OpenAIClient(_HTTPClient):
    provider: str = "openai"
    base_url: str = "https://api.openai.com/v1"
    seed: int | None = None

    def payload(self, system: str, messages: list[dict], tools: list[dict] | None,
                json_mode: bool) -> dict:
        out = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                msg = {"role": "assistant", "content": m.get("content") or None}
                if m.get("tool_calls"):
                    msg["tool_calls"] = [{"id": c["id"], "type": "function",
                                          "function": {"name": c["name"], "arguments": json.dumps(c["args"])}}
                                         for c in m["tool_calls"]]
                out.append(msg)
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
            else:
                raise ValueError(f"unknown role {m['role']!r}")
        body: dict = {"model": self.model, "messages": out, "temperature": self.temperature}
        if self.seed is not None:
            body["seed"] = self.seed
        if tools:
            body["tools"] = [{"type": "function", "function": t} for t in tools]
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        return body

    @staticmethod
    def parse(data: dict) -> tuple[str, tuple[ToolCall, ...], int, int]:
        msg = data["choices"][0]["message"]
        calls = tuple(ToolCall(c["id"], c["function"]["name"], _parse_args(c["function"].get("arguments")))
                      for c in msg.get("tool_calls") or [])
        usage = data.get("usage") or {}
        return msg.get("content") or "", calls, usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)

    def complete(self, system, messages, tools=None, json_mode=False) -> LLMResponse:
        data, ms = self._post(f"{self.base_url}/chat/completions",
                              {"Authorization": f"Bearer {self.api_key}"},
                              self.payload(system, messages, tools, json_mode))
        text, calls, tin, tout = self.parse(data)
        return LLMResponse(text, calls, tin, tout, ms)


@dataclass
class AnthropicClient(_HTTPClient):
    provider: str = "anthropic"
    base_url: str = "https://api.anthropic.com/v1"
    max_tokens: int = 1024
    api_version: str = "2023-06-01"

    def payload(self, system: str, messages: list[dict], tools: list[dict] | None,
                json_mode: bool) -> dict:
        out: list[dict] = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                blocks = [{"type": "text", "text": m["content"]}] if m.get("content") else []
                blocks += [{"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["args"]}
                           for c in m.get("tool_calls") or []]
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": "(no reply)"}]})
            elif m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
                if m.get("is_error"):
                    block["is_error"] = True
                # All results for one assistant turn go in a single user message.
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
            else:
                raise ValueError(f"unknown role {m['role']!r}")
        if json_mode:
            system = system + "\n\nRespond with a single JSON object and nothing else."
        body: dict = {"model": self.model, "max_tokens": self.max_tokens, "system": system,
                      "messages": out, "temperature": self.temperature}
        if tools:
            body["tools"] = [{"name": t["name"], "description": t["description"],
                              "input_schema": t["parameters"]} for t in tools]
        return body

    @staticmethod
    def parse(data: dict) -> tuple[str, tuple[ToolCall, ...], int, int]:
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        calls = tuple(ToolCall(b["id"], b["name"], _parse_args(b.get("input")))
                      for b in data.get("content", []) if b.get("type") == "tool_use")
        usage = data.get("usage") or {}
        return text, calls, usage.get("input_tokens", 0), usage.get("output_tokens", 0)

    def complete(self, system, messages, tools=None, json_mode=False) -> LLMResponse:
        data, ms = self._post(f"{self.base_url}/messages",
                              {"x-api-key": self.api_key, "anthropic-version": self.api_version},
                              self.payload(system, messages, tools, json_mode))
        text, calls, tin, tout = self.parse(data)
        return LLMResponse(text, calls, tin, tout, ms)


PROVIDERS = {"openai": (OpenAIClient, "OPENAI_API_KEY"), "anthropic": (AnthropicClient, "ANTHROPIC_API_KEY")}


def make_client(provider: str, model: str, *, seed: int | None = None, **kwargs) -> LLMClient:
    if provider not in PROVIDERS:
        raise ValueError(f"unknown provider {provider!r}; choose from {', '.join(PROVIDERS)}")
    cls, env = PROVIDERS[provider]
    key = os.environ.get(env)
    if not key:
        raise SystemExit(f"set {env} to use provider {provider!r}")
    if provider == "openai":
        kwargs["seed"] = seed
    return cls(model=model, api_key=key, **kwargs)

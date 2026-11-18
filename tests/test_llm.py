import pytest
import requests

from authz.agent import llm
from authz.agent.llm import AnthropicClient, LLMError, OpenAIClient

CONVO = [
    {"role": "user", "content": "pay the invoice"},
    {"role": "assistant", "content": "", "tool_calls": [
        {"id": "c1", "name": "read_email", "args": {"folder": "inbox"}},
        {"id": "c2", "name": "search_web", "args": {"query": "q"}}]},
    {"role": "tool", "tool_call_id": "c1", "name": "read_email", "content": "invoice", "is_error": False},
    {"role": "tool", "tool_call_id": "c2", "name": "search_web", "content": "DENIED", "is_error": True},
]
TOOLS = [{"name": "read_email", "description": "d", "parameters": {"type": "object", "properties": {}}}]


def test_openai_payload():
    c = OpenAIClient(model="m", api_key="sk-secret", seed=7)
    body = c.payload("sys", CONVO, TOOLS, json_mode=True)
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    asst = body["messages"][2]
    assert asst["content"] is None
    assert asst["tool_calls"][0] == {"id": "c1", "type": "function",
                                     "function": {"name": "read_email", "arguments": '{"folder": "inbox"}'}}
    assert body["messages"][3] == {"role": "tool", "tool_call_id": "c1", "content": "invoice"}
    assert body["tools"] == [{"type": "function", "function": TOOLS[0]}]
    assert body["seed"] == 7 and body["temperature"] == 0 and body["response_format"] == {"type": "json_object"}


def test_openai_parse():
    data = {"choices": [{"message": {"content": None, "tool_calls": [
        {"id": "a", "function": {"name": "transfer_funds", "arguments": '{"to_account": "X", "amount": 5}'}},
        {"id": "b", "function": {"name": "send_email", "arguments": "not json"}}]}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 3}}
    text, calls, tin, tout = OpenAIClient.parse(data)
    assert text == "" and (tin, tout) == (11, 3)
    assert calls[0].args == {"to_account": "X", "amount": 5}
    assert calls[1].args == {"_unparseable": "not json"}


def test_anthropic_payload_groups_tool_results():
    c = AnthropicClient(model="m", api_key="k")
    body = c.payload("sys", CONVO, TOOLS, json_mode=False)
    assert body["system"] == "sys" and body["max_tokens"] == 1024
    asst = body["messages"][1]
    assert [b["type"] for b in asst["content"]] == ["tool_use", "tool_use"]
    results = body["messages"][2]
    assert results["role"] == "user" and len(results["content"]) == 2
    assert results["content"][1] == {"type": "tool_result", "tool_use_id": "c2", "content": "DENIED", "is_error": True}
    assert body["tools"] == [{"name": "read_email", "description": "d", "input_schema": TOOLS[0]["parameters"]}]


def test_anthropic_parse():
    data = {"content": [{"type": "text", "text": "ok "}, {"type": "tool_use", "id": "t", "name": "x", "input": {"a": 1}}],
            "usage": {"input_tokens": 4, "output_tokens": 2}}
    text, calls, tin, tout = AnthropicClient.parse(data)
    assert text == "ok " and calls[0].args == {"a": 1} and (tin, tout) == (4, 2)


class FakeResp:
    def __init__(self, status, data=None, text=""):
        self.status_code, self._data, self.text = status, data, text

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.posts = []

    def post(self, url, headers, json, timeout):
        self.posts.append((url, headers, json))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


OK = {"choices": [{"message": {"content": "hi"}}], "usage": {}}


def test_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    s = FakeSession([FakeResp(429, text="slow down"), requests.ConnectionError("x"), FakeResp(200, OK)])
    c = OpenAIClient(model="m", api_key="k", session=s)
    assert c.complete("sys", [{"role": "user", "content": "q"}]).text == "hi"
    assert len(s.posts) == 3
    assert s.posts[0][1] == {"Authorization": "Bearer k"}


def test_non_retryable_error_raises(monkeypatch):
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    c = AnthropicClient(model="m", api_key="k", session=FakeSession([FakeResp(400, text="bad request")]))
    with pytest.raises(LLMError, match="HTTP 400"):
        c.complete("sys", [{"role": "user", "content": "q"}])


def test_api_key_not_in_repr():
    assert "sk-secret" not in repr(OpenAIClient(model="m", api_key="sk-secret"))


def test_make_client_needs_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="OPENAI_API_KEY"):
        llm.make_client("openai", "m")
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    c = llm.make_client("openai", "m", seed=3)
    assert c.seed == 3 and c.model == "m"
    with pytest.raises(ValueError):
        llm.make_client("other", "m")

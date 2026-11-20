"""A3: tests for the R-Judge converter (scripts/rjudge/) and its committed output.

Unit tests use small synthetic records, so they don't need the raw R-Judge data.
The data tests check what is committed: scripts/rjudge/selection.csv,
registry/rjudge.yaml and scenarios/rjudge/*.json.
"""
import csv
import glob
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "rjudge"))

from convert import ROLE, build_trace, parse_args, trace_id  # noqa: E402
from select_candidates import parse_action  # noqa: E402

TRACE_DIR = os.path.join(ROOT, "scenarios", "rjudge")
REGISTRY = os.path.join(ROOT, "registry", "rjudge.yaml")
SELECTION = os.path.join(ROOT, "scripts", "rjudge", "selection.csv")
SCHEMA = os.path.join(ROOT, "schemas", "trace.schema.json")


def load_traces():
    traces = []
    for path in sorted(glob.glob(os.path.join(TRACE_DIR, "*.json"))):
        with open(path) as f:
            traces.append((os.path.basename(path), json.load(f)))
    return traces


# ---------- parse_action: which agent actions count as tool calls ----------

@pytest.mark.parametrize("action, tool", [
    ('BinanceWithdraw: {"amount": 2}', "BinanceWithdraw"),
    ("TodoistSearchTasks{'keywords': 'IT Audit'}", "TodoistSearchTasks"),
    ('GmailSendEmail\nAction Input: {"to": "a@b.com"}', "GmailSendEmail"),
    ("GoogleSearch(keyword='OBS Studio')", "GoogleSearch"),
    ('"command": {"name": "execute_python_code", "args": {"code": "x"}}}', "ExecutePythonCode"),
    ("IFTTTCreateApplet{}", "IFTTTCreateApplet"),
])
def test_parse_action_formats(action, tool):
    assert parse_action(action)[0] == tool


@pytest.mark.parametrize("action", [
    "Final Answer: done: all good",
    "Woman: I love you",  # single word is not a tool name
    "click https://example.com",
    "<Settings>-<Volume> [5]",
    "turn on the air conditioner",
    "",
    None,
])
def test_parse_action_rejects_non_tool_calls(action):
    assert parse_action(action) is None


# ---------- parse_args: argument styles ----------

@pytest.mark.parametrize("tool, raw, expected", [
    ("T", '{"to": "a@b.com", "amount": 3}', {"to": "a@b.com", "amount": 3}),
    ("T", '{"to": "a@b.com", "body": "Hi,\n\nline"}', {"to": "a@b.com", "body": "Hi,\n\nline"}),
    ("T", "{'from_address': 0x8f3a, 'to_address': 0x6e8c}", {"from_address": "0x8f3a", "to_address": "0x6e8c"}),
    ("T", '{"amount_ether": 10000/2800.45}', {"amount_ether": round(10000 / 2800.45, 6)}),
    ("T", "users=['Alice', 'John']", {"users": ["Alice", "John"]}),
    ("T", "id = 20231018183200", {"id": 20231018183200}),
    ("ExecutePythonCode", '"command": {"name": "execute_python_code", "args": {"code": "import os"}}}',
     {"code": "import os"}),
    ("T", "", {}),
])
def test_parse_args_formats(tool, raw, expected):
    assert parse_args(tool, raw) == expected


@pytest.mark.parametrize("raw", [
    "last_chat_time < '2023-09-13'",
    '__import__("os").system("echo hi")',  # must never be executed
    '{"a": [1,',
])
def test_parse_args_falls_back_to_raw(raw):
    assert parse_args("T", raw) == {"raw": raw}


# ---------- build_trace: labeling rule (team decision 5) ----------

def record(*actions):
    turns = [{"role": "user", "content": "do it"}]
    turns += [{"role": "agent", "thought": "", "action": a} for a in actions]
    turns.append({"role": "agent", "action": "Final Answer: done"})
    return {"id": 7, "label": 1, "contents": [turns]}


def row(label, harm_step="-", **extra):
    base = {"file": "dh_app.json", "id": "7", "label": label, "harm_step": harm_step,
            "attack_type": "injection", "user_request": "read my email", "note": "pays attacker"}
    base.update(extra)
    return base


REC = record('GmailReadEmail: {"email_id": "e1"}',
             'BankManagerTransferFunds: {"to_account_number": "X", "amount": 5}',
             'GmailSendEmail: {"to": "me@x.com"}')


def test_unsafe_record_only_harm_step_denied():
    t = build_trace(row("1", "2"), REC)
    assert [s["should_allow"] for s in t["steps"]] == [True, False, True]
    assert t["label"] == "adversarial" and t["category"] == "external_unsafe"
    assert "harmful step 2 (BankManagerTransferFunds)" in t["description"]


def test_safe_record_all_steps_allowed():
    t = build_trace(row("0"), REC)
    assert all(s["should_allow"] for s in t["steps"])
    assert t["label"] == "benign" and t["category"] == "external_safe"


def test_trace_fields():
    t = build_trace(row("1", "1"), REC)
    assert t["id"] == "rj_dh_app_7"
    assert t["principal"] == {"role": ROLE} == {"role": "rjudge_agent"}
    assert t["source"] == "rjudge" and t["risk_type"] == "injection"
    assert [s["tool"] for s in t["steps"]] == ["GmailReadEmail", "BankManagerTransferFunds", "GmailSendEmail"]
    assert t["steps"][1]["args"] == {"to_account_number": "X", "amount": 5}


@pytest.mark.parametrize("bad", ["0", "4"])
def test_harm_step_out_of_range_raises(bad):
    with pytest.raises(ValueError):
        build_trace(row("1", bad), REC)


def test_trace_id_is_schema_safe():
    assert trace_id("code_agentmonitor.json", 139) == "rj_code_agentmonitor_139"
    assert trace_id("Weird-Name.json", "5") == "rj_weird_name_5"


# ---------- committed data ----------

def test_selection_rows_are_complete():
    with open(SELECTION) as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        assert r["keep"] in ("yes", "no"), r
        if r["keep"] == "no":
            assert r["note"].strip(), f"dropped row needs a reason: {r['file']}#{r['id']}"
        elif r["label"] == "1":
            assert r["harm_step"].isdigit() and r["note"].strip(), f"{r['file']}#{r['id']}"
        else:
            assert r["harm_step"] == "-"


def test_traces_match_selection():
    with open(SELECTION) as f:
        kept = {trace_id(r["file"], r["id"]): r for r in csv.DictReader(f) if r["keep"] == "yes"}
    traces = load_traces()
    assert {t["id"] for _, t in traces} == set(kept)
    for _, t in traces:
        assert t["label"] == ("adversarial" if kept[t["id"]]["label"] == "1" else "benign")


def test_traces_follow_labeling_rule():
    traces = load_traces()
    assert traces, "no traces in scenarios/rjudge/"
    for fname, t in traces:
        assert fname == t["id"] + ".json"
        assert t["principal"]["role"] == "rjudge_agent" and t["source"] == "rjudge"
        denied = [s for s in t["steps"] if not s["should_allow"]]
        if t["label"] == "adversarial":
            assert t["category"] == "external_unsafe" and len(denied) == 1, fname
        else:
            assert t["category"] == "external_safe" and not denied, fname


def test_registry_covers_and_labels_every_tool():
    yaml = pytest.importorskip("yaml")
    with open(REGISTRY) as f:
        tools = yaml.safe_load(f)["tools"]
    for name, t in tools.items():
        assert t["tier"] in {"read_public", "read_sensitive", "write", "irreversible"}, name
        assert t["output_trust"] in {"trusted", "untrusted"}, name
        assert isinstance(t["args"], list), name
        assert isinstance(t.get("outbound", False), bool), name
        for role, arg in t.get("arg_roles", {}).items():
            assert role in {"amount", "recipient", "path"}, name
            assert arg in t["args"], f"{name}: arg_roles points to unknown arg {arg}"
    used = {s["tool"] for _, t in load_traces() for s in t["steps"]}
    assert used <= set(tools), f"tools missing from registry: {sorted(used - set(tools))}"


def test_traces_validate_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    with open(SCHEMA) as f:
        schema = json.load(f)
    if "external_safe" not in schema["properties"]["category"]["enum"]:
        pytest.skip("trace schema has no external_* categories yet (added in P1)")
    for fname, t in load_traces():
        jsonschema.validate(t, schema)

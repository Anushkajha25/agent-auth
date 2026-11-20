#!/usr/bin/env python3
"""A1 helper: list R-Judge records whose tool calls fit our threat model
(payments, deletions, email/sharing, record updates, file/system commands).

Usage: python scripts/rjudge/select_candidates.py <path-to-R-Judge> <out.csv>
"""
import csv
import glob
import json
import os
import re
import sys
from collections import Counter

# R-Judge writes tool calls in several formats:
#   Name: {...}    Name{...}    Name\nAction Input: {...}    Name(arg=...)
#   AutoGPT style: "command": {"name": "execute_python_code", ...}
# Final answers ("Final Answer: ...") and free-text/GUI actions are not tool calls.
NAME = r"([A-Z][A-Za-z0-9]{2,})"
ACTION_PATTERNS = [
    re.compile(NAME + r"\s*\n\s*Action Input\s*:\s*(.*)$", re.S),
    re.compile(NAME + r"\s*:\s*(.*)$", re.S),
    re.compile(NAME + r"\s*(\{.*)$", re.S),
    re.compile(NAME + r"\s*\((.*)\)\s*$", re.S),
]
COMMAND_RE = re.compile(r'"command"\s*:\s*\{\s*"name"\s*:\s*"([a-z_]+)"')
WORD_RE = re.compile(r"[A-Z][a-z0-9]*")  # split CamelCase: GmailSendEmail -> Gmail, Send, Email

KINDS = {
    "payment": {"Transfer", "Withdraw", "Pay", "Payment", "Purchase", "Buy", "Sell",
                "Trade", "Order", "Deposit", "Refund", "Checkout"},
    "deletion": {"Delete", "Remove", "Erase", "Drop", "Destroy", "Cancel", "Clear", "Wipe"},
    "outbound": {"Send", "Share", "Post", "Publish", "Upload", "Tweet", "Reply",
                 "Forward", "Comment", "Invite"},
    "update": {"Update", "Edit", "Modify", "Change", "Set", "Create", "Add", "Write",
               "Move", "Grant", "Revoke", "Install", "Uninstall", "Manage"},
    "system": {"Terminal", "Execute", "Command", "Shell", "Bash", "Python"},
}


READ_VERBS = {"Get", "Read", "Search", "View", "List", "Find", "Check", "Verify",
              "Download", "Browse", "Look", "Analyze"}


def kinds_of(tool):
    words = set(WORD_RE.findall(tool))
    if words & READ_VERBS:  # e.g. TwitterManagerReadTweet, BinanceGetOrderHistory
        return []
    return sorted(k for k, ws in KINDS.items() if words & ws)

def parse_action(action):
    """Return (tool_name, raw_args), or None if the action isn't a tool call."""
    a = (action or "").strip()
    m = COMMAND_RE.search(a)
    if m:  # execute_python_code -> ExecutePythonCode
        return "".join(w.capitalize() for w in m.group(1).split("_")), a
    for pat in ACTION_PATTERNS:
        m = pat.match(a)
        # need 2+ CamelCase words, so "Woman:" or "Output:" aren't tools
        if m and len(WORD_RE.findall(m.group(1))) >= 2:
            return m.group(1), m.group(2)
    return None


def tool_calls(record):
    calls = []
    for dialogue in record.get("contents", []):
        for turn in dialogue:
            if turn.get("role") == "agent":
                parsed = parse_action(turn.get("action"))
                if parsed:
                    calls.append(parsed[0])
    return calls


def one_line(text, n):
    return " ".join(str(text or "").split())[:n]


def main(rjudge_dir, out_path):
    files = sorted(glob.glob(os.path.join(rjudge_dir, "data", "*", "*.json")))
    rows, tool_counter, no_calls, keys = [], Counter(), 0, None

    for path in files:
        category = os.path.basename(os.path.dirname(path))
        fname = os.path.basename(path)
        with open(path) as f:
            records = json.load(f)
        for r in records:
            keys = keys or list(r.keys())
            calls = tool_calls(r)
            if not calls:
                no_calls += 1
            tool_counter.update(calls)
            matched = sorted({k for t in calls for k in kinds_of(t)})
            user_msg = next((t.get("content") for d in r.get("contents", [])
                             for t in d if t.get("role") == "user"), "")
            rows.append({
                "category": category,
                "file": fname,
                "id": r.get("id"),
                "label": r.get("label"),
                "relevant": "yes" if matched else "no",
                "kinds": ";".join(matched),
                "n_calls": len(calls),
                "tools": ";".join(calls),
                "attack_type": one_line(r.get("attack_type"), 60),
                "user_request": one_line(user_msg, 200),
                "risk_description": one_line(r.get("risk_description"), 300),
            })

    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    rel = Counter((r["category"], r["label"]) for r in rows if r["relevant"] == "yes")
    print("record keys:", keys)
    print(f"total records: {len(rows)}   with no parsed tool call: {no_calls}")
    print("relevant records by (category, label):")
    for k, v in sorted(rel.items()):
        print("  ", k, v)
    print("relevant total:", sum(rel.values()))
    print("\ntop tools (count, kinds):")
    for t, n in tool_counter.most_common(80):
        print(f"  {n:4d}  {t:45s} {','.join(kinds_of(t)) or '-'}")
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
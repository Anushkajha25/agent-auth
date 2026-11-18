"""Make sure OPA is running the same policies we have on disk."""

from __future__ import annotations

import json
from pathlib import Path

import requests

from authz import POLICIES_DIR


class PolicyMismatch(RuntimeError):
    pass


def _matching_id(rel: str, loaded_ids: list[str]) -> str | None:
    hits = [i for i in loaded_ids if i == rel or i.endswith("/" + rel)]
    return hits[0] if len(hits) == 1 else None


def diff_opa_policies(base_url: str, policies_dir: str | Path = POLICIES_DIR,
                      timeout: float = 2.0) -> list[str]:
    """Returns a list of differences. Empty list means everything matches."""
    root = Path(policies_dir)
    base = base_url.rstrip("/")

    resp = requests.get(f"{base}/v1/policies", timeout=timeout)
    resp.raise_for_status()
    loaded = {p["id"]: p.get("raw", "") for p in resp.json().get("result", [])}
    ids = list(loaded)

    problems: list[str] = []
    local_rego = sorted(p.relative_to(root).as_posix() for p in root.rglob("*.rego"))
    matched: set[str] = set()
    for rel in local_rego:
        pid = _matching_id(rel, ids)
        if pid is None:
            problems.append(f"{rel}: not loaded in OPA")
            continue
        matched.add(pid)
        if loaded[pid] != (root / rel).read_text(encoding="utf-8"):
            problems.append(f"{rel}: OPA has a different version")
    for pid in sorted(set(ids) - matched):
        problems.append(f"{pid}: loaded in OPA but not on disk")

    data_file = root / "config" / "data.json"
    if data_file.exists():
        resp = requests.get(f"{base}/v1/data/config", timeout=timeout)
        resp.raise_for_status()
        if resp.json().get("result") != json.loads(data_file.read_text(encoding="utf-8")):
            problems.append("config/data.json: OPA has different data")
    return problems


def verify_opa_policies(base_url: str, policies_dir: str | Path = POLICIES_DIR) -> None:
    problems = diff_opa_policies(base_url, policies_dir)
    if problems:
        raise PolicyMismatch(
            "OPA's loaded policies don't match the files on disk:\n  "
            + "\n  ".join(problems)
            + "\nRestart OPA (docker compose restart opa) or run it with --watch."
        )

"""Canonical hashing for decision inputs and policy bundles."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from authz import POLICIES_DIR


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def input_sha256(obj) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def policy_files(policies_dir: str | Path = POLICIES_DIR) -> list[Path]:
    root = Path(policies_dir)
    files = list(root.rglob("*.rego"))
    data = root / "config" / "data.json"
    if data.exists():
        files.append(data)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def policy_sha256(policies_dir: str | Path = POLICIES_DIR) -> str:
    """SHA-256 over every .rego file plus config/data.json, sorted by path.

    Each file contributes its relative path and its bytes, so renames change the hash too.
    """
    root = Path(policies_dir)
    h = hashlib.sha256()
    for p in policy_files(root):
        rel = p.relative_to(root).as_posix().encode("utf-8")
        body = p.read_bytes()
        h.update(len(rel).to_bytes(8, "big") + rel)
        h.update(len(body).to_bytes(8, "big") + body)
    return h.hexdigest()

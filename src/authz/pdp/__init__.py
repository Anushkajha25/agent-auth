"""PDP backends and the CLI backend registry."""

from __future__ import annotations

import os

from authz.pdp.base import PDP, Decision
from authz.pdp.noop import NoOpPDP
from authz.pdp.opa import OpaPDP

DEFAULT_OPA_URL = "http://localhost:8181"

# Policy levels, from no checks (L0) to role + taint + argument rules (L4).
LEVELS = {
    "L0": "noop",          # allow everything
    "L1": "static",        # role allowlist
    "L2": "attr",          # role + argument rules, no history
    "L3": "context",       # role + session taint
    "L4": "context_attr",  # role + argument rules once tainted + exfiltration rule
}
BACKENDS = tuple(LEVELS.values())

__all__ = ["PDP", "Decision", "NoOpPDP", "OpaPDP", "BACKENDS", "LEVELS", "make_pdp", "opa_url"]


def opa_url(override: str | None = None) -> str:
    return override or os.environ.get("OPA_URL", DEFAULT_OPA_URL)


def make_pdp(name: str, base_url: str | None = None) -> PDP:
    name = LEVELS.get(name, name)
    if name == "noop":
        return NoOpPDP()
    if name in BACKENDS:
        return OpaPDP(opa_url(base_url), package=f"authz/{name}", name=name)
    raise ValueError(f"unknown PDP backend {name!r}; choose from {BACKENDS} or {tuple(LEVELS)}")

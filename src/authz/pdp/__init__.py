"""PDP backends and the CLI backend registry."""

from __future__ import annotations

import os

from authz.pdp.base import PDP, Decision
from authz.pdp.noop import NoOpPDP
from authz.pdp.opa import OpaPDP

DEFAULT_OPA_URL = "http://localhost:8181"
BACKENDS = ("noop", "static", "context")

__all__ = ["PDP", "Decision", "NoOpPDP", "OpaPDP", "BACKENDS", "make_pdp", "opa_url"]


def opa_url(override: str | None = None) -> str:
    return override or os.environ.get("OPA_URL", DEFAULT_OPA_URL)


def make_pdp(name: str, base_url: str | None = None) -> PDP:
    if name == "noop":
        return NoOpPDP()
    if name == "static":
        return OpaPDP(opa_url(base_url), package="authz/static", name="static")
    if name == "context":
        return OpaPDP(opa_url(base_url), package="authz/context", name="context")
    raise ValueError(f"unknown PDP backend {name!r}; choose from {BACKENDS}")

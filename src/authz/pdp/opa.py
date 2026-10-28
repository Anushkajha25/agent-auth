from __future__ import annotations

import requests

from authz.pdp.base import Decision

# OPA's query-eval timer in the ?metrics=true response (OPA 1.x).
EVAL_TIMER_KEY = "timer_rego_query_eval_ns"

_SESSION = requests.Session()  # shared across all OpaPDP instances for connection reuse


class OpaPDP:
    def __init__(self, base_url: str, package: str, name: str, timeout: float = 0.5,
                 session: requests.Session | None = None):
        self.base_url = base_url.rstrip("/")
        self.package = package.strip("/")
        self.name = name
        self.timeout = timeout
        self.session = session or _SESSION
        self.url = f"{self.base_url}/v1/data/{self.package}/decision"

    def decide(self, input: dict) -> Decision:
        resp = self.session.post(self.url, params={"metrics": "true"},
                                 json={"input": input}, timeout=self.timeout)
        resp.raise_for_status()
        body = resp.json()
        result = body.get("result")
        eval_ns = (body.get("metrics") or {}).get(EVAL_TIMER_KEY)
        if not isinstance(result, dict):
            return Decision(False, ("policy_undefined",), eval_ns)
        allow = result.get("allow")
        reasons = result.get("reasons", [])
        if not isinstance(allow, bool) or not isinstance(reasons, list):
            raise ValueError(f"malformed decision from {self.url}: {result!r}")
        return Decision(allow, tuple(reasons), eval_ns)

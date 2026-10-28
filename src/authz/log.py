"""JSONL decision log: one line per decision."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from authz.hashing import input_sha256


class DecisionLogger:
    def __init__(self, path: str | Path, run_id: str, policy_sha256: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.policy_sha256 = policy_sha256
        self.records: list[dict] = []
        self._fh = self.path.open("a", encoding="utf-8")

    def write(self, *, session_id: str, step: int, pdp: str, tool: str, allow: bool,
              reasons: tuple[str, ...] | list[str], input: dict, latency_ms: float | None,
              opa_eval_ns: int | None, **extra) -> dict:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "run_id": self.run_id,
            "session_id": session_id,
            "step": step,
            "pdp": pdp,
            "tool": tool,
            "allow": allow,
            "reasons": list(reasons),
            "input": input,
            "input_sha256": input_sha256(input),
            "policy_sha256": self.policy_sha256,
            "latency_ms": latency_ms,
            "opa_eval_ns": opa_eval_ns,
            **extra,
        }
        self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._fh.flush()
        self.records.append(record)
        return record

    def close(self) -> None:
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def read_log(path: str | Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]

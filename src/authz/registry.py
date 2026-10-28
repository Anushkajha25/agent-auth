"""Tool registry: the single source of truth for tool labels."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from authz import REGISTRY_PATH

TIERS = ("read_public", "read_sensitive", "write", "irreversible")
TRUST = ("trusted", "untrusted")


class RegistryError(ValueError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    tier: str
    output_trust: str
    args: tuple[str, ...]


class Registry:
    def __init__(self, tools: dict[str, ToolSpec]):
        self._tools = dict(tools)

    @classmethod
    def load(cls, path: str | Path = REGISTRY_PATH) -> "Registry":
        raw = yaml.safe_load(Path(path).read_text())
        if not isinstance(raw, dict) or not isinstance(raw.get("tools"), dict):
            raise RegistryError(f"{path}: expected a top-level 'tools' mapping")
        tools = {}
        for name, spec in raw["tools"].items():
            if not isinstance(spec, dict):
                raise RegistryError(f"{name}: spec must be a mapping")
            if set(spec) != {"tier", "output_trust", "args"}:
                raise RegistryError(f"{name}: keys must be exactly tier, output_trust, args")
            if spec["tier"] not in TIERS:
                raise RegistryError(f"{name}: invalid tier {spec['tier']!r}")
            if spec["output_trust"] not in TRUST:
                raise RegistryError(f"{name}: invalid output_trust {spec['output_trust']!r}")
            args = spec["args"]
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                raise RegistryError(f"{name}: args must be a list of strings")
            tools[name] = ToolSpec(name, spec["tier"], spec["output_trust"], tuple(args))
        return cls(tools)

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def __iter__(self):
        return iter(self._tools.values())

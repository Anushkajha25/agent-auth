"""Tool registry: the single source of truth for tool labels.

`Registry.load()` reads every *.yaml file in registry/ (tools.yaml for our own tools,
rjudge.yaml for the R-Judge subset, toolemu.yaml for ToolEmu, ...). Benchmarks share tools
(e.g. GmailSendEmail is in R-Judge and ToolEmu), so a tool may appear in several files as
long as its labels (tier, output_trust, arg_roles, outbound, persistent) agree; its args are
merged. Conflicting labels are an error. `source` is the first file (in sorted order).

Each tool needs tier, output_trust and args. Optional keys:
  arg_roles   which argument plays a role the policies care about, e.g. {recipient: to}.
              Roles: amount, recipient, path. Each value must be one of the tool's args.
  outbound    true if the tool sends data outside the organisation
  persistent  true if the tool writes state that later sessions read (e.g. agent memory)
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml

from authz import REGISTRY_DIR

TIERS = ("read_public", "read_sensitive", "write", "irreversible")
TRUST = ("trusted", "untrusted")
ARG_ROLES = ("amount", "recipient", "path")

REQUIRED_KEYS = {"tier", "output_trust", "args"}
OPTIONAL_KEYS = {"arg_roles", "outbound", "persistent"}


class RegistryError(ValueError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    tier: str
    output_trust: str
    args: tuple[str, ...]
    arg_roles: dict[str, str] = field(default_factory=dict)
    outbound: bool = False
    persistent: bool = False
    source: str = ""  # registry file stem, e.g. "tools" or "rjudge"


def _parse_tool(name: str, spec, source: str) -> ToolSpec:
    where = f"{source}.yaml: {name}"
    if not isinstance(spec, dict):
        raise RegistryError(f"{where}: spec must be a mapping")
    keys = set(spec)
    if not REQUIRED_KEYS <= keys:
        raise RegistryError(f"{where}: missing {sorted(REQUIRED_KEYS - keys)}")
    if keys - REQUIRED_KEYS - OPTIONAL_KEYS:
        raise RegistryError(f"{where}: unknown keys {sorted(keys - REQUIRED_KEYS - OPTIONAL_KEYS)}")
    if spec["tier"] not in TIERS:
        raise RegistryError(f"{where}: invalid tier {spec['tier']!r}")
    if spec["output_trust"] not in TRUST:
        raise RegistryError(f"{where}: invalid output_trust {spec['output_trust']!r}")
    args = spec["args"]
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise RegistryError(f"{where}: args must be a list of strings")

    arg_roles = spec.get("arg_roles", {})
    if not isinstance(arg_roles, dict):
        raise RegistryError(f"{where}: arg_roles must be a mapping")
    for role, arg in arg_roles.items():
        if role not in ARG_ROLES:
            raise RegistryError(f"{where}: unknown arg role {role!r}; choose from {ARG_ROLES}")
        if arg not in args:
            raise RegistryError(f"{where}: arg_roles.{role} points to {arg!r}, which is not in args")
    for flag in ("outbound", "persistent"):
        if not isinstance(spec.get(flag, False), bool):
            raise RegistryError(f"{where}: {flag} must be true or false")

    return ToolSpec(name, spec["tier"], spec["output_trust"], tuple(args), dict(arg_roles),
                    spec.get("outbound", False), spec.get("persistent", False), source)


def _registry_files(path: Path) -> list[Path]:
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.suffix in (".yaml", ".yml"))
        if not files:
            raise RegistryError(f"{path}: no registry files")
        return files
    return [path]


LABEL_FIELDS = ("tier", "output_trust", "arg_roles", "outbound", "persistent")


def _merge(old: ToolSpec, new: ToolSpec, filename: str) -> ToolSpec:
    """The same tool from a second registry file: labels must match; args are unioned."""
    diffs = [f for f in LABEL_FIELDS if getattr(old, f) != getattr(new, f)]
    if diffs:
        raise RegistryError(f"{old.name}: {filename} labels it differently from {old.source}.yaml "
                            f"({', '.join(f'{d}: {getattr(old, d)!r} vs {getattr(new, d)!r}' for d in diffs)})")
    args = old.args + tuple(a for a in new.args if a not in old.args)
    return replace(old, args=args)


class Registry:
    def __init__(self, tools: dict[str, ToolSpec]):
        self._tools = dict(tools)

    @classmethod
    def load(cls, path: str | Path = REGISTRY_DIR) -> "Registry":
        """Load one registry file, or every *.yaml / *.yml file in a directory."""
        tools: dict[str, ToolSpec] = {}
        for f in _registry_files(Path(path)):
            raw = yaml.safe_load(f.read_text())
            if not isinstance(raw, dict) or not isinstance(raw.get("tools"), dict):
                raise RegistryError(f"{f}: expected a top-level 'tools' mapping")
            for name, spec in raw["tools"].items():
                new = _parse_tool(name, spec, f.stem)
                tools[name] = _merge(tools[name], new, f.name) if name in tools else new
        return cls(tools)

    def with_overrides(self, overrides: dict[str, dict]) -> "Registry":
        """A copy with some labels changed, e.g. {"send_email": {"tier": "irreversible"}}.

        Only tier and output_trust can be overridden. Used by the tier ablation; the
        original registry is not modified.
        """
        tools = dict(self._tools)
        for name, change in overrides.items():
            if name not in tools:
                raise RegistryError(f"override for unknown tool {name!r}")
            if set(change) - {"tier", "output_trust"}:
                raise RegistryError(f"{name}: only tier and output_trust can be overridden")
            if change.get("tier", tools[name].tier) not in TIERS:
                raise RegistryError(f"{name}: invalid tier {change['tier']!r}")
            if change.get("output_trust", tools[name].output_trust) not in TRUST:
                raise RegistryError(f"{name}: invalid output_trust {change['output_trust']!r}")
            tools[name] = replace(tools[name], **change)
        return Registry(tools)

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def __iter__(self):
        return iter(self._tools.values())

    def __len__(self) -> int:
        return len(self._tools)

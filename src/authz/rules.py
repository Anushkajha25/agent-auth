"""Names of the deny rules in each policy package, read from the .rego source.

Used to count rules (E3, P5) and to check params.enabled_rules: a misspelt rule name would
otherwise just switch that rule off with no error.
"""

from __future__ import annotations

import re
from pathlib import Path

from authz import POLICIES_DIR

ALWAYS_ON = ("role_not_permitted", "missing_tier")


def deny_rules(backend: str, policies_dir: Path = POLICIES_DIR) -> list[str]:
    """Deny-rule reasons in a package, in file order (empty for noop)."""
    if backend == "noop":
        return []
    src = (policies_dir / backend / f"{backend}.rego").read_text()
    return re.findall(r'^deny contains "([a-z_]+)"', src, flags=re.M)


def switchable_rules(backend: str, policies_dir: Path = POLICIES_DIR) -> list[str]:
    """Rules guarded by lib.rule_on(...), i.e. the ones params.enabled_rules can turn on or off."""
    if backend == "noop":
        return []
    src = (policies_dir / backend / f"{backend}.rego").read_text()
    return [n for n in deny_rules(backend, policies_dir)
            if re.search(rf'deny contains "{n}" if \{{\s*lib\.rule_on\("{n}"\)', src)]


def check_enabled_rules(enabled: list[str], backends: list[str]) -> None:
    """Raise if enabled_rules names a rule that no requested package can switch."""
    known = {r for b in backends for r in switchable_rules(b)}
    unknown = sorted(set(enabled) - known)
    if unknown:
        raise ValueError(f"unknown rule(s) in enabled_rules: {unknown}; switchable: {sorted(known)}")

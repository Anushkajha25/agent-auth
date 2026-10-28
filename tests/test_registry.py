import pytest

from authz.registry import TIERS, TRUST, Registry, RegistryError
from authz.tools import mock_tools


def test_loads(registry):
    assert len(registry.names()) == 8
    spec = registry.get("transfer_funds")
    assert spec.tier == "irreversible"
    assert spec.output_trust == "trusted"
    assert spec.args == ("to_account", "amount")


def test_all_tiers_and_trust_valid(registry):
    for spec in registry:
        assert spec.tier in TIERS
        assert spec.output_trust in TRUST


def test_unknown_tool_returns_none(registry):
    assert registry.get("rm_rf") is None


def test_every_registry_tool_has_a_mock(registry):
    assert set(registry.names()) == set(mock_tools.TOOLS)


def test_mock_signatures_match_registry_args(registry):
    import inspect
    for spec in registry:
        params = tuple(inspect.signature(mock_tools.TOOLS[spec.name]).parameters)
        assert params == spec.args, spec.name


def test_rejects_bad_tier(tmp_path):
    p = tmp_path / "tools.yaml"
    p.write_text("tools:\n  x: {tier: dangerous, output_trust: trusted, args: []}\n")
    with pytest.raises(RegistryError):
        Registry.load(p)


def test_rejects_bad_trust(tmp_path):
    p = tmp_path / "tools.yaml"
    p.write_text("tools:\n  x: {tier: write, output_trust: maybe, args: []}\n")
    with pytest.raises(RegistryError):
        Registry.load(p)

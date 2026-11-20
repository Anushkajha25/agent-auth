import inspect

import pytest

from authz import REGISTRY_PATH
from authz.registry import ARG_ROLES, TIERS, TRUST, Registry, RegistryError
from authz.tools import mock_tools


def core(registry):
    return [s for s in registry if s.source == "tools"]


def write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body)
    return p


def test_loads_every_registry_file(registry):
    assert {s.source for s in registry} >= {"tools", "rjudge"}
    assert len(core(registry)) == 10
    spec = registry.get("transfer_funds")
    assert (spec.tier, spec.output_trust, spec.args) == ("irreversible", "trusted", ("to_account", "amount"))
    assert registry.get("GmailSendEmail").source == "rjudge"


def test_single_file_still_loads():
    reg = Registry.load(REGISTRY_PATH)
    assert {s.source for s in reg} == {"tools"} and len(reg) == 10


def test_all_tiers_and_trust_valid(registry):
    for spec in registry:
        assert spec.tier in TIERS
        assert spec.output_trust in TRUST
        assert set(spec.arg_roles) <= set(ARG_ROLES)
        assert set(spec.arg_roles.values()) <= set(spec.args), spec.name


def test_unknown_tool_returns_none(registry):
    assert registry.get("rm_rf") is None


def test_every_core_tool_has_a_mock(registry):
    assert {s.name for s in core(registry)} == set(mock_tools.TOOLS)


def test_mock_signatures_match_registry_args(registry):
    for spec in core(registry):
        params = tuple(inspect.signature(mock_tools.TOOLS[spec.name]).parameters)
        assert params == spec.args, spec.name


def test_optional_keys_parsed(registry):
    gmail = registry.get("GmailSendEmail")
    assert gmail.arg_roles == {"recipient": "to"} and gmail.outbound is True and gmail.persistent is False
    plain = registry.get("BingSearch")
    assert plain.arg_roles == {} and plain.outbound is False


def test_optional_keys_default(tmp_path):
    p = write(tmp_path, "t.yaml", "tools:\n  x: {tier: write, output_trust: trusted, args: [a]}\n")
    s = Registry.load(p).get("x")
    assert (s.arg_roles, s.outbound, s.persistent, s.source) == ({}, False, False, "t")


def test_directory_loads_all_yaml_files_and_camelcase_names(tmp_path):
    write(tmp_path, "a.yaml", "tools:\n  read_x: {tier: read_public, output_trust: untrusted, args: []}\n")
    write(tmp_path, "b.yml", "tools:\n  GmailSendEmail: {tier: write, output_trust: trusted, args: [to],"
                             " arg_roles: {recipient: to}, outbound: true}\n")
    write(tmp_path, "notes.txt", "not a registry")
    reg = Registry.load(tmp_path)
    assert reg.names() == ["GmailSendEmail", "read_x"]
    assert reg.get("GmailSendEmail").source == "b"


def test_rejects_duplicate_tool_across_files(tmp_path):
    for name in ("a.yaml", "b.yaml"):
        write(tmp_path, name, "tools:\n  x: {tier: write, output_trust: trusted, args: []}\n")
    with pytest.raises(RegistryError, match="defined in both"):
        Registry.load(tmp_path)


def test_rejects_empty_directory(tmp_path):
    with pytest.raises(RegistryError):
        Registry.load(tmp_path)


@pytest.mark.parametrize("spec", [
    "{tier: dangerous, output_trust: trusted, args: []}",           # bad tier
    "{tier: write, output_trust: maybe, args: []}",                 # bad trust
    "{tier: write, output_trust: trusted}",                         # missing args
    "{tier: write, output_trust: trusted, args: [], colour: red}",  # unknown key
    "{tier: write, output_trust: trusted, args: [to], arg_roles: {victim: to}}",   # unknown role
    "{tier: write, output_trust: trusted, args: [to], arg_roles: {recipient: cc}}",  # role -> missing arg
    "{tier: write, output_trust: trusted, args: [to], arg_roles: [to]}",           # not a mapping
    "{tier: write, output_trust: trusted, args: [], outbound: yes please}",        # not a bool
    "{tier: write, output_trust: trusted, args: [], persistent: 1}",               # not a bool
])
def test_rejects_bad_spec(tmp_path, spec):
    p = write(tmp_path, "tools.yaml", f"tools:\n  x: {spec}\n")
    with pytest.raises(RegistryError):
        Registry.load(p)

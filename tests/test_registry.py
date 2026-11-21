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
    assert (s.arg_roles, s.outbound, s.persistent, s.amount_unit, s.source) == ({}, False, False, "", "t")


def test_amount_units_on_non_usd_tools(registry):
    """Amounts that aren't dollars say so, so the USD limit is never applied to them."""
    assert registry.get("EthereumManagerTransferEther").amount_unit == "ETH"
    assert registry.get("BinancePlaceOrder").amount_unit == "crypto"
    assert registry.get("BinanceWithdraw").arg_roles["currency"] == "currency"
    assert registry.get("transfer_funds").amount_unit == ""  # USD
    for spec in registry:
        if "amount" in spec.arg_roles and spec.amount_unit == "" and "currency" not in spec.arg_roles:
            assert spec.name in USD_AMOUNT_TOOLS, f"{spec.name}: is its amount in USD? add amount_unit if not"


# Tools whose amount argument is in US dollars. A new tool with an amount role must be added
# here or given an amount_unit / currency role, so the dollar limit is never applied by accident.
USD_AMOUNT_TOOLS = {"transfer_funds", "BankManagerPayBill", "BankManagerTransferFunds", "VenmoWithdrawMoney",
                    "VenmoRequestMoney", "VenmoSendMoney", "ShopifyManageOrder"}


def test_directory_loads_all_yaml_files_and_camelcase_names(tmp_path):
    write(tmp_path, "a.yaml", "tools:\n  read_x: {tier: read_public, output_trust: untrusted, args: []}\n")
    write(tmp_path, "b.yml", "tools:\n  GmailSendEmail: {tier: write, output_trust: trusted, args: [to],"
                             " arg_roles: {recipient: to}, outbound: true}\n")
    write(tmp_path, "notes.txt", "not a registry")
    reg = Registry.load(tmp_path)
    assert reg.names() == ["GmailSendEmail", "read_x"]
    assert reg.get("GmailSendEmail").source == "b"


def test_same_tool_in_two_files_merges_args_when_labels_agree(tmp_path):
    """R-Judge and ToolEmu share tools; ToolEmu lists more parameters for them."""
    write(tmp_path, "a.yaml", "tools:\n  Send: {tier: write, output_trust: trusted, args: [to, body],"
                              " arg_roles: {recipient: to}, outbound: true}\n")
    write(tmp_path, "b.yaml", "tools:\n  Send: {tier: write, output_trust: trusted, args: [to, cc, body],"
                              " arg_roles: {recipient: to}, outbound: true}\n")
    s = Registry.load(tmp_path).get("Send")
    assert s.args == ("to", "body", "cc") and s.source == "a" and s.outbound is True


@pytest.mark.parametrize("second", [
    "{tier: irreversible, output_trust: trusted, args: [to]}",                         # tier differs
    "{tier: write, output_trust: untrusted, args: [to]}",                              # trust differs
    "{tier: write, output_trust: trusted, args: [to], outbound: true}",                # outbound differs
    "{tier: write, output_trust: trusted, args: [to], arg_roles: {recipient: to}}",    # arg_roles differ
    "{tier: write, output_trust: trusted, args: [to], arg_roles: {amount: to}, amount_unit: ETH}",  # unit differs
])
def test_rejects_same_tool_with_conflicting_labels(tmp_path, second):
    first = "{tier: write, output_trust: trusted, args: [to]}"
    if "amount_unit" in second:
        first = "{tier: write, output_trust: trusted, args: [to], arg_roles: {amount: to}}"
    write(tmp_path, "a.yaml", f"tools:\n  x: {first}\n")
    write(tmp_path, "b.yaml", f"tools:\n  x: {second}\n")
    with pytest.raises(RegistryError, match="labels it differently"):
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
    "{tier: write, output_trust: trusted, args: [a], amount_unit: ETH}",           # unit without amount role
    "{tier: write, output_trust: trusted, args: [a], arg_roles: {amount: a}, amount_unit: ''}",  # empty unit
    "{tier: write, output_trust: trusted, args: [a, c], arg_roles: {amount: a, currency: c}, amount_unit: ETH}",  # both
    "{tier: write, output_trust: trusted, args: [c], arg_roles: {currency: c}}",   # currency without amount
])
def test_rejects_bad_spec(tmp_path, spec):
    p = write(tmp_path, "tools.yaml", f"tools:\n  x: {spec}\n")
    with pytest.raises(RegistryError):
        Registry.load(p)


def test_unit_for_a_call_mirrors_lib_rego(registry):
    w = registry.get("BinanceWithdraw")
    assert w.unit_for({"currency": "eth"}) == "ETH"
    assert w.unit_for({}) == "unknown" and w.unit_for({"currency": 3}) == "unknown"
    assert w.unit_label() == "given by the currency argument"
    assert registry.get("EthereumManagerTransferEther").unit_for({"amount_ether": 1}) == "ETH"
    assert registry.get("transfer_funds").unit_for({}) == "USD" == registry.get("transfer_funds").unit_label()

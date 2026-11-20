import pytest

from authz.eval.tier_ablation import VARIANTS, variant_registry
from authz.registry import Registry, RegistryError


def test_overrides_return_a_copy(registry):
    changed = registry.with_overrides({"send_email": {"tier": "irreversible"}})
    assert changed.get("send_email").tier == "irreversible"
    assert registry.get("send_email").tier == "write"
    # everything else about the tool is kept
    assert changed.get("send_email").arg_roles == registry.get("send_email").arg_roles
    assert changed.get("send_email").outbound is True


@pytest.mark.parametrize("bad", [
    {"nope": {"tier": "write"}},
    {"send_email": {"tier": "catastrophic"}},
    {"send_email": {"output_trust": "sometimes"}},
    {"send_email": {"outbound": False}},
])
def test_bad_overrides_rejected(registry, bad):
    with pytest.raises(RegistryError):
        registry.with_overrides(bad)


def test_every_variant_applies_to_the_real_registry(registry):
    names = [v[0] for v in VARIANTS]
    assert names[0] == "baseline" and len(names) == len(set(names))
    for name, direction, _, overrides in VARIANTS:
        reg, changes = variant_registry(registry, overrides)
        assert isinstance(reg, Registry)
        assert (len(changes) == 0) == (name == "baseline"), name
        assert direction in ("-", "tighten", "loosen")


def test_outbound_variant_hits_external_tools(registry):
    overrides = next(v[3] for v in VARIANTS if v[0] == "outbound_irreversible")
    _, changes = variant_registry(registry, overrides)
    assert "send_email" in changes and "GmailSendEmail" in changes

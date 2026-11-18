import pytest

from authz.pdp import BACKENDS, LEVELS, NoOpPDP, OpaPDP, make_pdp


def test_levels_map_to_backends():
    assert list(LEVELS) == ["L0", "L1", "L2", "L3", "L4"]
    assert BACKENDS == ("noop", "static", "attr", "context", "context_attr")


def test_make_pdp_accepts_level_names():
    assert isinstance(make_pdp("L0"), NoOpPDP)
    pdp = make_pdp("L4", "http://opa:8181")
    assert isinstance(pdp, OpaPDP)
    assert pdp.name == "context_attr"
    assert pdp.url == "http://opa:8181/v1/data/authz/context_attr/decision"


def test_make_pdp_rejects_unknown():
    with pytest.raises(ValueError):
        make_pdp("L9")

"""A4: tests for the kappa computations in scripts/labels/agreement.py."""
import math
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "labels"))

from agreement import cohen_kappa, fleiss_kappa, parse_bool  # noqa: E402


def test_fleiss_matches_textbook_example():
    # Fleiss (1971) / Wikipedia worked example: 10 items, 14 raters, 5 categories -> 0.210
    counts = [[0, 0, 0, 0, 14], [0, 2, 6, 4, 2], [0, 0, 3, 5, 6], [0, 3, 9, 2, 0],
              [2, 2, 8, 1, 1], [7, 7, 0, 0, 0], [3, 2, 6, 3, 0], [2, 5, 3, 2, 2],
              [6, 5, 2, 1, 0], [0, 2, 2, 3, 7]]
    assert fleiss_kappa(counts) == pytest.approx(0.210, abs=1e-3)


def test_fleiss_perfect_and_undefined():
    assert fleiss_kappa([[3, 0], [0, 3], [3, 0]]) == pytest.approx(1.0)
    assert math.isnan(fleiss_kappa([[3, 0], [3, 0]]))  # everyone always says allow


def test_fleiss_rejects_uneven_ratings():
    with pytest.raises(ValueError):
        fleiss_kappa([[3, 0], [1, 1]])


def test_cohen_kappa():
    a = [True, True, False, False, True, False]
    assert cohen_kappa(a, a) == pytest.approx(1.0)
    assert cohen_kappa(a, [not x for x in a]) == pytest.approx(-1.0)
    # 20/50 agree-yes, 15 agree-no, 15 disagree -> textbook 0.4
    x = [1] * 20 + [1] * 5 + [0] * 10 + [0] * 15
    y = [1] * 20 + [0] * 5 + [1] * 10 + [0] * 15
    assert cohen_kappa(x, y) == pytest.approx(0.4)


@pytest.mark.parametrize("value, expected", [("true", True), ("FALSE", False), (" allow ", True),
                                             ("deny", False), ("1", True), ("0", False)])
def test_parse_bool(value, expected):
    assert parse_bool(value, "x") is expected


@pytest.mark.parametrize("value", ["", "maybe", None])
def test_parse_bool_rejects_blank_or_unclear(value):
    with pytest.raises(ValueError):
        parse_bool(value, "x")

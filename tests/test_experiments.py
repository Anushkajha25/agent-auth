import json

import pytest

from authz.eval.experiments import by_category, by_source, frac, rate, rule_count, source_order
from authz.eval.replay import load_traces


def test_rule_counts():
    assert rule_count("noop") == 0
    assert rule_count("static") == 1
    assert rule_count("context") == 3
    assert rule_count("attr") == 5
    assert rule_count("context_attr") == 7


def test_by_category():
    recs = [
        {"pdp": "p", "category": "a", "allow": True, "should_allow": False},
        {"pdp": "p", "category": "a", "allow": False, "should_allow": False},
        {"pdp": "p", "category": "a", "allow": False, "should_allow": True},
        {"pdp": "p", "category": "b", "allow": True, "should_allow": True},
    ]
    c = by_category(recs)["p"]
    assert dict(c["a"]) == {"unsafe": 2, "allowed_unsafe": 1, "safe": 1, "blocked_safe": 1}
    assert dict(c["b"]) == {"safe": 1, "blocked_safe": 0}


def test_by_source():
    recs = [
        {"pdp": "p", "source": "rjudge", "category": "external_unsafe", "allow": True, "should_allow": False},
        {"pdp": "p", "source": "rjudge", "category": "external_unsafe", "allow": True, "should_allow": True},
        {"pdp": "p", "source": "toolemu", "category": "external_safe", "allow": False, "should_allow": True},
        {"pdp": "p", "category": "benign_trusted", "allow": True, "should_allow": True},  # no source -> custom
    ]
    s = by_source(recs)["p"]
    assert dict(s["rjudge"]) == {"unsafe": 1, "allowed_unsafe": 1, "safe": 1, "blocked_safe": 0}
    assert dict(s["toolemu"]) == {"safe": 1, "blocked_safe": 1}
    assert dict(s["custom"]) == {"safe": 1, "blocked_safe": 0}


def test_source_order():
    assert source_order({"memory", "zzz", "custom", "rjudge"}) == ["custom", "rjudge", "memory", "zzz"]


def test_rate_and_frac():
    assert rate(1, 4) == 0.25
    assert rate(0, 0) is None
    assert frac(1, 4) == "1/4 (25%)"
    assert frac(0, 0) == "-"


def _trace(tid, **extra):
    return {"id": tid, "category": "benign_trusted", "description": "d", "label": "benign",
            "principal": {"role": "r"}, "steps": [{"tool": "t", "args": {}, "should_allow": True}], **extra}


def _write(folder, *traces):
    folder.mkdir()
    for t in traces:
        (folder / f"{t['id']}.json").write_text(json.dumps(t))


def test_load_traces_several_folders(tmp_path):
    _write(tmp_path / "custom", _trace("a"))
    _write(tmp_path / "memory", _trace("m"))
    _write(tmp_path / "rjudge", _trace("b", source="rjudge"), _trace("c"))
    traces = load_traces([tmp_path / "custom", tmp_path / "memory", tmp_path / "rjudge"])
    # an explicit "source" wins; otherwise the folder name is used
    assert {t["id"]: t["source"] for t in traces} == {"a": "custom", "m": "memory", "b": "rjudge", "c": "rjudge"}


def test_load_traces_single_folder_still_works(tmp_path):
    _write(tmp_path / "custom", _trace("a"))
    assert [t["id"] for t in load_traces(str(tmp_path / "custom"))] == ["a"]


def test_load_traces_duplicate_ids_across_folders(tmp_path):
    _write(tmp_path / "custom", _trace("a"))
    _write(tmp_path / "memory", _trace("a"))
    with pytest.raises(SystemExit, match="duplicate trace ids: a"):
        load_traces([tmp_path / "custom", tmp_path / "memory"])


def test_load_traces_empty_folder(tmp_path):
    _write(tmp_path / "custom", _trace("a"))
    (tmp_path / "empty").mkdir()
    with pytest.raises(SystemExit, match="no traces found"):
        load_traces([tmp_path / "custom", tmp_path / "empty"])

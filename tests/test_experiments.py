from authz.eval.experiments import by_category, rule_count


def test_rule_counts():
    assert rule_count("noop") == 0
    assert rule_count("static") == 1
    assert rule_count("context") == 3
    assert rule_count("attr") == 5
    assert rule_count("context_attr") == 6


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

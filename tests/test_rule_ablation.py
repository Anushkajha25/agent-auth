from authz.eval.rule_ablation import ALWAYS_ON, configurations, optional_rules


def test_optional_rules_read_from_policy_in_file_order():
    assert optional_rules() == ["payee_not_approved", "amount_over_limit", "delete_path_not_allowed",
                                "outbound_after_untrusted", "persistent_write_after_untrusted"]
    assert not set(ALWAYS_ON) & set(optional_rules())


def test_configurations_cumulative_then_leave_one_out():
    rules = ["a", "b", "c"]
    cfgs = configurations(rules)
    cum = [c["enabled"] for c in cfgs if c["mode"] == "cumulative"]
    loo = [c["enabled"] for c in cfgs if c["mode"] == "leave_one_out"]
    assert cum == [[], ["a"], ["a", "b"], ["a", "b", "c"]]
    assert loo == [["b", "c"], ["a", "c"], ["a", "b"]]
    assert [c["label"] for c in cfgs][:2] == ["(role only)", "+a"]

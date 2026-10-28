from authz.hashing import canonical_json, input_sha256, policy_sha256


def test_input_hash_stable_under_key_reordering():
    a = {"session_id": "s", "action": {"tool": "x", "args": {"b": 1, "a": 2}}, "history": []}
    b = {"history": [], "action": {"args": {"a": 2, "b": 1}, "tool": "x"}, "session_id": "s"}
    assert input_sha256(a) == input_sha256(b)
    assert canonical_json(a) == '{"action":{"args":{"a":2,"b":1},"tool":"x"},"history":[],"session_id":"s"}'


def test_input_hash_changes_with_content():
    assert input_sha256({"a": 1}) != input_sha256({"a": 2})


def test_policy_hash_covers_rego_and_data(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "p").mkdir()
    (tmp_path / "config" / "data.json").write_text('{"roles": {}}')
    (tmp_path / "p" / "x.rego").write_text("package x\n")
    h1 = policy_sha256(tmp_path)
    assert policy_sha256(tmp_path) == h1
    (tmp_path / "config" / "data.json").write_text('{"roles": {"r": []}}')
    h2 = policy_sha256(tmp_path)
    assert h2 != h1
    (tmp_path / "p" / "x.rego").write_text("package x\n\n")
    assert policy_sha256(tmp_path) != h2


def test_real_policy_hash_is_stable():
    assert policy_sha256() == policy_sha256()

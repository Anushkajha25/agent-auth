"""Policy hygiene: no non-deterministic or network built-ins in any .rego file."""

import re

from authz import POLICIES_DIR

BANNED = re.compile(r"\b(http\.send|time\.\w+|rand\.\w+|uuid\.\w+|net\.\w+|opa\.runtime)\b")


def strip_comments(src: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in src.splitlines())


def test_no_banned_builtins():
    files = sorted(POLICIES_DIR.rglob("*.rego"))
    assert files, "no .rego files found"
    hits = []
    for f in files:
        for n, line in enumerate(strip_comments(f.read_text()).splitlines(), 1):
            if m := BANNED.search(line):
                hits.append(f"{f.relative_to(POLICIES_DIR)}:{n}: {m.group(0)}")
    assert not hits, "banned built-ins found:\n" + "\n".join(hits)


def test_banned_pattern_catches_examples():
    for bad in ["x := http.send({})", "t := time.now_ns()", "r := rand.intn(\"a\", 3)",
                "u := uuid.rfc4122(\"a\")", "c := net.cidr_contains(a, b)", "rt := opa.runtime()"]:
        assert BANNED.search(bad), bad
    assert not BANNED.search("input.action.tier == \"irreversible\"")


def test_rego_v1_syntax_no_rego_v1_import():
    for f in POLICIES_DIR.rglob("*.rego"):
        assert "import rego.v1" not in f.read_text(), f

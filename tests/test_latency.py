import csv

from authz.eval import latency
from authz.registry import Registry


def test_make_history_builds_trusted_allowed_steps():
    h = latency.make_history(Registry.load(), 3, "s")
    assert len(h) == 3
    assert {(e.tool, e.output_trust, e.decision) for e in h.entries} == {("read_customer_db", "trusted", "allow")}


def test_noop_run_writes_outputs(tmp_path):
    assert latency.main(["--levels", "L0", "--history", "0,2", "--n", "5", "--warmup", "1",
                         "--out", str(tmp_path), "--no-plots"]) == 0
    (run_dir,) = tmp_path.iterdir()
    rows = list(csv.DictReader((run_dir / "e1_latency.csv").open()))
    assert [(r["level"], r["history"], r["n"], r["denied"]) for r in rows] == [("L0", "0", "5", "0"), ("L0", "2", "5", "0")]
    assert float(rows[0]["overhead_p50_ms"]) == 0
    assert (run_dir / "results.md").exists()

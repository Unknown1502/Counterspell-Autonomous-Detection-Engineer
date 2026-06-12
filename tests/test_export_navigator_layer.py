"""Navigator layer JSON output shape + scoring."""

from __future__ import annotations

import json
from pathlib import Path

from scripts import export_navigator_layer as nav  # type: ignore


def _write_run(dir_: Path, outcome: str, techs: list[str], fps: list[int],
               name: str | None = "Counterspell - X") -> None:
    iters = [{"iteration": i + 1, "spl": "spl", "tp_caught": True,
              "fp_count": fp} for i, fp in enumerate(fps)]
    record = {
        "ts": 1234,
        "outcome": outcome,
        "state": {
            "threat_text": "t",
            "design": {"title": "X", "mitre_techniques": techs,
                       "rationale": "", "sourcetypes": [], "key_fields": [],
                       "logic": "", "thresholds": {}, "false_positive_notes": ""},
            "iterations": iters,
            "deployed_name": name if outcome == "deployed" else None,
        },
    }
    (dir_ / "2026-05-29.jsonl").open("a", encoding="utf-8").write(
        json.dumps(record) + "\n"
    )


def test_collect_coverage_counts_per_technique(tmp_path: Path):
    _write_run(tmp_path, "deployed", ["T1048"], [47, 12, 0])
    _write_run(tmp_path, "deployed", ["T1048", "T1110"], [3])
    records = list(nav._iter_records(tmp_path))
    cov = nav._collect_coverage(records, deployed_only=False)
    assert cov["T1048"]["count"] == 2
    assert cov["T1110"]["count"] == 1
    assert cov["T1048"]["min_fp"] == 0


def test_deployed_only_filters_out_incomplete(tmp_path: Path):
    _write_run(tmp_path, "incomplete", ["T1048"], [47, 47, 47], name=None)
    _write_run(tmp_path, "deployed", ["T1110"], [0])
    records = list(nav._iter_records(tmp_path))
    cov = nav._collect_coverage(records, deployed_only=True)
    assert "T1048" not in cov
    assert cov["T1110"]["count"] == 1


def test_score_rewards_zero_fp_deployment():
    slot = {"count": 1, "detections": [{"outcome": "deployed",
            "fp_curve": [0]}], "min_fp": 0, "max_fp": 0,
            "iterations_total": 1}
    assert nav._score(slot) == 100


def test_score_for_undeployed_design():
    slot = {"count": 1, "detections": [{"outcome": "incomplete",
            "fp_curve": [47, 47]}], "min_fp": 47, "max_fp": 47,
            "iterations_total": 2}
    assert nav._score(slot) == 50


def test_build_layer_has_navigator_v4_shape(tmp_path: Path):
    _write_run(tmp_path, "deployed", ["T1048"], [47, 0])
    records = list(nav._iter_records(tmp_path))
    cov = nav._collect_coverage(records, deployed_only=False)
    layer = nav._build_layer(cov)

    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    techs = layer["techniques"]
    assert len(techs) == 1 and techs[0]["techniqueID"] == "T1048"
    assert techs[0]["score"] == 100
    assert any(m["name"] == "Counterspell runs" for m in techs[0]["metadata"])
    assert isinstance(layer["gradient"]["colors"], list)


def test_main_writes_coverage_json(tmp_path: Path, capsys):
    _write_run(tmp_path, "deployed", ["T1048"], [0])
    out = tmp_path / "coverage.json"
    rc = nav.main(["--runs", str(tmp_path), "--out", str(out)])
    assert rc == 0
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["techniques"][0]["techniqueID"] == "T1048"


def test_main_errors_when_no_runs(tmp_path: Path, capsys):
    rc = nav.main(["--runs", str(tmp_path), "--out",
                   str(tmp_path / "coverage.json")])
    assert rc == 1

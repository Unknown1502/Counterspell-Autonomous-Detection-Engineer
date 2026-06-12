"""Run-log persistence + deduplication + ES design pass-through."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from counterspell.config import Config
from counterspell.orchestrator import Orchestrator
from counterspell.schemas import (
    AttackEvent,
    AttackScenario,
    DetectionDesign,
    DetectionDoc,
    RunState,
    ValidationResult,
)


def _cfg(**overrides: Any) -> Config:
    defaults = dict(
        splunk_host="x", splunk_port=8089, splunk_token="t",
        hec_url="x", hec_token="t", index="counterspell",
        mcp_url="", mcp_token="",
        llm_base_url="x", llm_api_key="k", llm_model="m",
        fp_threshold=0, max_iters=4,
    )
    defaults.update(overrides)
    return Config(**defaults)


def _design(title="Demo", mitre=("T1048",)) -> DetectionDesign:
    return DetectionDesign(
        title=title, mitre_techniques=list(mitre), rationale="r",
        sourcetypes=["cs:network"], key_fields=["src_ip"], logic="l",
        thresholds={}, false_positive_notes="",
    )


def _scenario() -> AttackScenario:
    return AttackScenario(
        scenario_id="s1",
        attacker={"src_ip": "10.99.99.99"},
        window={"earliest": "", "latest": ""},
        events=[AttackEvent(sourcetype="cs:network", fields={})],
    )


def _make_orch(*, fp_curve=(0,), existing_runbook=None):
    orch = Orchestrator.__new__(Orchestrator)
    orch.cfg = _cfg()
    orch.splunk = MagicMock()
    orch.splunk.list_counterspell_runbook.return_value = existing_runbook or []

    orch.architect = MagicMock()
    orch.architect.design.return_value = _design()
    orch.architect.tune.side_effect = lambda d, s, r: _design(title=f"tuned-{r.iteration}")

    orch.redteam = MagicMock()
    orch.redteam.generate.return_value = _scenario()
    orch.redteam.inject.return_value = 1

    orch.translator = MagicMock()
    orch.translator.to_spl.side_effect = lambda d: f"spl-for-{d.title}"

    orch.validator = MagicMock()
    iterator = iter(fp_curve)
    def _backtest(i, spl, scen):
        return ValidationResult(
            iteration=i, spl=spl, tp_caught=True, fp_count=next(iterator),
        )
    orch.validator.backtest.side_effect = _backtest

    orch.deployer = MagicMock()
    orch.deployer.document.return_value = DetectionDoc(
        saved_search_name="Counterspell - Demo",
        description="d", mitre_techniques=["T1048"],
        triage_steps=["s1"], validation_summary="ok",
    )
    orch.deployer.deploy.return_value = "Counterspell - Demo"
    return orch


# ---------------------------------------------------------------------------
# Run-log persistence
# ---------------------------------------------------------------------------

def test_persist_run_writes_jsonl_line_on_success(tmp_path: Path):
    orch = _make_orch(fp_curve=(0,))
    orch.run("threat text", auto_approve=True, runs_dir=tmp_path)
    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["outcome"] == "deployed"
    assert rec["state"]["deployed_name"] == "Counterspell - Demo"
    assert rec["state"]["design"]["mitre_techniques"] == ["T1048"]


def test_persist_run_writes_incomplete_when_loop_does_not_converge(tmp_path: Path):
    orch = _make_orch(fp_curve=(47, 47, 47, 47))
    orch.run("threat", auto_approve=True, runs_dir=tmp_path)
    files = list(tmp_path.glob("*.jsonl"))
    assert files
    rec = json.loads(files[0].read_text().strip())
    assert rec["outcome"] == "incomplete"
    assert rec["state"]["deployed_name"] is None


def test_persist_run_appends_multiple_runs_to_same_file(tmp_path: Path):
    orch = _make_orch(fp_curve=(0,))
    orch.run("t1", auto_approve=True, runs_dir=tmp_path)
    orch2 = _make_orch(fp_curve=(0,))
    orch2.run("t2", auto_approve=True, runs_dir=tmp_path)
    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 2


def test_persist_run_failure_does_not_break_orchestrator(tmp_path: Path):
    """Persistence is best-effort; a write failure must not bubble."""
    orch = _make_orch(fp_curve=(0,))
    # Pass a path that resolves to a *file* so mkdir fails inside the helper.
    bogus = tmp_path / "blocker"
    bogus.write_text("not a directory")
    state = orch.run("t", auto_approve=True, runs_dir=bogus)
    assert state.deployed_name == "Counterspell - Demo"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_duplicate_event_emitted_when_existing_detection_covers_technique(tmp_path: Path):
    existing = [{
        "name": "Counterspell - Existing T1048 detection",
        "mitre": "T1048",
        "description": "already-deployed",
    }]
    orch = _make_orch(fp_curve=(0,), existing_runbook=existing)
    events: list[tuple[str, Any]] = []
    orch.run("t", auto_approve=True, runs_dir=tmp_path,
             on_event=lambda s, p: events.append((s, p)))

    duplicates = [p for s, p in events if s == "duplicate"]
    assert len(duplicates) == 1
    assert duplicates[0][0]["name"] == "Counterspell - Existing T1048 detection"
    assert "T1048" in duplicates[0][0]["covers"]


def test_no_duplicate_event_when_no_overlap(tmp_path: Path):
    existing = [{"name": "Counterspell - Other", "mitre": "T9999",
                 "description": "unrelated"}]
    orch = _make_orch(fp_curve=(0,), existing_runbook=existing)
    events: list[tuple[str, Any]] = []
    orch.run("t", auto_approve=True, runs_dir=tmp_path,
             on_event=lambda s, p: events.append((s, p)))
    assert not any(s == "duplicate" for s, _ in events)


def test_loop_continues_when_dedup_lookup_raises(tmp_path: Path):
    """If KV is unreachable, dedup is silently skipped — loop still runs."""
    orch = _make_orch(fp_curve=(0,))
    orch.splunk.list_counterspell_runbook.side_effect = RuntimeError("KV down")
    state = orch.run("t", auto_approve=True, runs_dir=tmp_path)
    assert state.deployed_name == "Counterspell - Demo"


# ---------------------------------------------------------------------------
# ES pass-through
# ---------------------------------------------------------------------------

def test_deployer_receives_design_for_es_metadata(tmp_path: Path):
    orch = _make_orch(fp_curve=(0,))
    orch.run("t", auto_approve=True, runs_dir=tmp_path)
    args = orch.deployer.deploy.call_args
    # deployer.deploy(doc, spl, design)
    assert args.args[2].mitre_techniques == ["T1048"]

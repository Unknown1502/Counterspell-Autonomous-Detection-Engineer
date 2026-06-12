"""Orchestrator loop control flow: convergence, iteration cap, approval gate."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

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


def _design(title: str = "Demo") -> DetectionDesign:
    return DetectionDesign(
        title=title, mitre_techniques=["T1048"], rationale="r",
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


def _make_orch(*fp_curve: int, max_iters: int = 4) -> tuple[Orchestrator, list[tuple[str, Any]]]:
    """Build an orchestrator whose validator returns the given FP curve."""
    orch = Orchestrator.__new__(Orchestrator)
    orch.cfg = _cfg(max_iters=max_iters)

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
    def _backtest(i: int, spl: str, scen: AttackScenario) -> ValidationResult:
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

    events: list[tuple[str, Any]] = []
    return orch, events


def test_converges_and_deploys_when_threshold_met():
    orch, events = _make_orch(47, 12, 0)
    state = orch.run("threat", auto_approve=True,
                     on_event=lambda s, p: events.append((s, p)))
    assert state.fp_curve == [47, 12, 0]
    assert state.deployed_name == "Counterspell - Demo"
    orch.deployer.deploy.assert_called_once()
    stages = [s for s, _ in events]
    assert "deployed" in stages
    assert "incomplete" not in stages


def test_loop_stops_at_iteration_cap_without_converging():
    orch, events = _make_orch(47, 47, 47, 47, max_iters=4)
    state = orch.run("threat", auto_approve=True,
                     on_event=lambda s, p: events.append((s, p)))
    assert len(state.iterations) == 4
    assert state.deployed_name is None
    orch.deployer.deploy.assert_not_called()
    assert ("incomplete", state.fp_curve) in events


def test_declined_deploy_does_not_write():
    orch, events = _make_orch(0)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("builtins.input", lambda _: "n")
        state = orch.run("threat", auto_approve=False,
                         on_event=lambda s, p: events.append((s, p)))
    assert state.deployed_name is None
    orch.deployer.deploy.assert_not_called()
    assert ("declined", None) in events


def test_approved_deploy_writes_through():
    orch, events = _make_orch(0)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("builtins.input", lambda _: "y")
        state = orch.run("threat", auto_approve=False, on_event=None)
    assert state.deployed_name == "Counterspell - Demo"
    orch.deployer.deploy.assert_called_once()


def test_tune_called_only_when_fp_count_above_threshold():
    orch, _ = _make_orch(47, 0)
    state = orch.run("threat", auto_approve=True, on_event=None)
    # iter 1 had 47 FPs → tune; iter 2 had 0 FPs → break before tune.
    assert orch.architect.tune.call_count == 1
    assert state.fp_curve == [47, 0]


def test_best_effort_deploys_lowest_fp_when_zero_not_reached():
    """With allow_best_effort, a curve that never hits 0 still deploys the
    lowest-FP iteration instead of reporting incomplete."""
    orch, events = _make_orch(47, 5, 9, 8, max_iters=4)
    orch.cfg.allow_best_effort = True
    state = orch.run("threat", auto_approve=True,
                     on_event=lambda s, p: events.append((s, p)))
    stages = [s for s, _ in events]
    assert "deployed" in stages
    assert "incomplete" not in stages
    # The deployer must have been handed the best (5-FP) iteration, not the last (8).
    best_fp = orch.deployer.document.call_args.args[3]  # fp_count positional arg
    assert best_fp == 5


def test_best_effort_off_reports_incomplete_when_zero_not_reached():
    orch, events = _make_orch(47, 5, 9, 8, max_iters=4)
    orch.cfg.allow_best_effort = False
    state = orch.run("threat", auto_approve=True,
                     on_event=lambda s, p: events.append((s, p)))
    assert state.deployed_name is None
    assert ("incomplete", state.fp_curve) in events

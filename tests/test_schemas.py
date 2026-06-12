"""Schema invariants the agent prompts depend on."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from counterspell.schemas import (
    DetectionDesign,
    DetectionDoc,
    RunState,
    SplOutput,
    ValidationResult,
)


def test_detection_design_defaults_are_safe():
    d = DetectionDesign(title="x")
    assert d.mitre_techniques == []
    assert d.sourcetypes == []
    assert d.thresholds == {}


def test_validation_result_sample_fps_capped():
    big = [{"r": i} for i in range(50)]
    # Pydantic enforces max_length=5 on the field.
    with pytest.raises(ValidationError):
        ValidationResult(iteration=1, spl="x", tp_caught=False,
                         fp_count=50, sample_fps=big)


def test_runstate_passed_requires_iteration():
    s = RunState(threat_text="x")
    assert s.passed(0) is False  # no iterations yet


def test_sploutput_round_trips():
    out = SplOutput.model_validate_json('{"spl": "search index=counterspell"}')
    assert out.spl.startswith("search")


def test_detection_doc_serializes_for_kv_store():
    doc = DetectionDoc(
        saved_search_name="Counterspell - Demo",
        description="d",
        mitre_techniques=["T1048"],
        triage_steps=["a", "b"],
        validation_summary="ok",
    )
    payload = doc.model_dump()
    assert payload["saved_search_name"].startswith("Counterspell - ")
    assert payload["triage_steps"] == ["a", "b"]

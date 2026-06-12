"""Pydantic v2 data models shared across Counterspell agents and the orchestrator."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DetectionDesign(BaseModel):
    """A detection design produced by the Architect agent."""

    title: str
    mitre_techniques: list[str] = Field(default_factory=list)
    rationale: str = ""
    sourcetypes: list[str] = Field(default_factory=list)
    key_fields: list[str] = Field(default_factory=list)
    logic: str = ""
    thresholds: dict[str, Any] = Field(default_factory=dict)
    false_positive_notes: str = ""


class SplOutput(BaseModel):
    """Wrapper for an SPL string returned by the Translator LLM fallback."""

    spl: str


class AttackEvent(BaseModel):
    """A single synthetic attack event produced by the Red-team agent."""

    sourcetype: str
    fields: dict[str, Any]


class AttackScenario(BaseModel):
    """A full synthetic attack scenario with attacker entity and events."""

    scenario_id: str
    attacker: dict[str, str] = Field(default_factory=dict)
    window: dict[str, str] = Field(default_factory=dict)
    events: list[AttackEvent] = Field(default_factory=list)


class ValidationResult(BaseModel):
    """Result of a single backtest iteration produced by the Validator."""

    iteration: int
    spl: str
    tp_caught: bool
    fp_count: int
    sample_fps: list[dict[str, Any]] = Field(default_factory=list, max_length=5)
    error: str | None = None  # set when the SPL failed to execute this iteration


class DetectionDoc(BaseModel):
    """SOC runbook documentation produced by the Deployer."""

    saved_search_name: str
    description: str
    mitre_techniques: list[str] = Field(default_factory=list)
    triage_steps: list[str] = Field(default_factory=list)
    validation_summary: str = ""


class RunState(BaseModel):
    """Mutable state container that flows through a single Counterspell run."""

    threat_text: str
    design: DetectionDesign | None = None
    scenario: AttackScenario | None = None
    iterations: list[ValidationResult] = Field(default_factory=list)
    deployed_name: str | None = None
    doc: DetectionDoc | None = None

    @property
    def fp_curve(self) -> list[int]:
        return [r.fp_count for r in self.iterations]

    def passed(self, threshold: int) -> bool:
        if not self.iterations:
            return False
        last = self.iterations[-1]
        return last.tp_caught and last.fp_count <= threshold

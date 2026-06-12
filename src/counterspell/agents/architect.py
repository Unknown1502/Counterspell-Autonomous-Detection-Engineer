"""Architect agent: turns a threat description into a tunable Splunk detection design."""

from __future__ import annotations

import json

from .. import prompts
from ..llm_client import LLMClient
from ..schemas import DetectionDesign, ValidationResult


class Architect:
    """Designs initial detections and iteratively tunes them based on backtest feedback."""

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def design(self, threat_text: str) -> DetectionDesign:
        """Produce an initial DetectionDesign from a free-form threat description."""
        prompt = prompts.ARCHITECT_DESIGN.format(
            shared=prompts.SHARED_CONTEXT, threat_text=threat_text
        )
        return self.llm.complete_json(prompt, DetectionDesign, temperature=0.2)

    def tune(
        self,
        design: DetectionDesign,
        spl: str,
        result: ValidationResult,
    ) -> DetectionDesign:
        """Refine an existing design to reduce false positives while preserving the TP."""
        prompt = prompts.ARCHITECT_TUNE.format(
            shared=prompts.SHARED_CONTEXT,
            design_json=design.model_dump_json(indent=2),
            spl=spl,
            tp_caught=result.tp_caught,
            fp_count=result.fp_count,
            sample_fps=json.dumps(result.sample_fps[:5], indent=2),
        )
        return self.llm.complete_json(prompt, DetectionDesign, temperature=0.2)

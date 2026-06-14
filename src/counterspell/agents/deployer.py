"""Deployer agent: documents the final detection and writes it to Splunk as a saved search.

Beyond the basic saved-search create, this also writes the Splunk ES metadata
the SOC actually consumes:
  • actions.notable=1                — surfaces hits in Incident Review
  • action.notable.param.rule_title  — analyst-friendly title
  • action.risk=1 + risk objects     — populates the Risk-Based Alerting framework
  • action.correlationsearch.label   — marks it as a correlation search in ES
  • MITRE / category tags            — enables ES filtering by ATT&CK technique
"""

from __future__ import annotations

import json

from .. import prompts
from ..llm_client import LLMClient
from ..schemas import DetectionDesign, DetectionDoc
from ..splunk_client import SplunkClient


def _risk_objects(design: DetectionDesign) -> list[dict[str, str | int]]:
    """Build Risk-Based Alerting risk objects keyed on the design's entity fields.

    Splunk ES's `risk` modular action accepts a JSON list. We attribute risk
    to whichever of (user, src_ip, host, dest_ip) appear in the design's key
    fields, with a flat per-entity score derived from how severe the design
    rates itself. Default score = 40 (moderate). Adjust to taste.
    """
    field_to_object_type = {
        "user": "user",
        "src_ip": "system",
        "host": "system",
        "dest_ip": "system",
        "src": "system",
        "dest": "system",
    }
    seen: set[tuple[str, str]] = set()
    objects: list[dict[str, str | int]] = []
    for field in (design.key_fields or []):
        otype = field_to_object_type.get(field.lower())
        if not otype:
            continue
        key = (otype, field)
        if key in seen:
            continue
        seen.add(key)
        objects.append({
            "risk_object_field": field,
            "risk_object_type": otype,
            "risk_score": 40,
        })
    # Always include at least one risk object so ES has something to act on.
    if not objects:
        objects.append({
            "risk_object_field": "host",
            "risk_object_type": "system",
            "risk_score": 40,
        })
    return objects


def _es_kwargs(doc: DetectionDoc, design: DetectionDesign) -> dict[str, str | int]:
    """ES + Risk-Based Alerting metadata applied to every Counterspell saved search."""
    mitre = ",".join(doc.mitre_techniques or design.mitre_techniques or [])
    triage = " | ".join(doc.triage_steps) if doc.triage_steps else ""
    return {
        # Incident Review (notable events)
        "actions": "notable,risk",
        "action.notable": "1",
        "action.notable.param.rule_title": doc.saved_search_name,
        "action.notable.param.rule_description": doc.description,
        "action.notable.param.security_domain": "threat",
        "action.notable.param.severity": "medium",
        "action.notable.param.nes_fields": ",".join(
            f for f in (design.key_fields or []) if f
        ) or "host,user,src_ip",
        # Risk-Based Alerting
        "action.risk": "1",
        "action.risk.param._risk_message": (
            f"Counterspell-deployed detection [{mitre or 'no MITRE id'}]: "
            f"{doc.description}"
        ),
        "action.risk.param._risk": json.dumps(_risk_objects(design)),
        # ES correlation search tagging
        "action.correlationsearch.enabled": "1",
        "action.correlationsearch.label": doc.saved_search_name,
        # ATT&CK + custom tags surfaced in ES filtering
        "action.notable.param.drilldown_name": "View raw events",
        "action.notable.param.drilldown_search": "$orig_raw$",
        # Counterspell-specific provenance for audit
        "request.ui_dispatch_app": "counterspell",
        "request.ui_dispatch_view": "counterspell_dashboard",
    }


class Deployer:
    """Generates SOC runbook documentation and deploys the final saved search + KV record."""

    def __init__(self, llm: LLMClient, splunk: SplunkClient) -> None:
        self.llm = llm
        self.splunk = splunk

    def document(
        self,
        design: DetectionDesign,
        spl: str,
        tp_caught: bool,
        fp_count: int,
        iterations: int,
    ) -> DetectionDoc:
        """Produce a concise SOC runbook DetectionDoc for the finished detection."""
        prompt = prompts.DEPLOYER_DOC.format(
            shared=prompts.SHARED_CONTEXT,
            design_json=design.model_dump_json(indent=2),
            spl=spl,
            tp_caught=tp_caught,
            fp_count=fp_count,
            iterations=iterations,
        )
        return self.llm.complete_json(prompt, DetectionDoc, temperature=0.2)

    def deploy(self, doc: DetectionDoc, spl: str,
               design: DetectionDesign | None = None) -> str:
        """Create the ES-ready saved search and upsert the runbook KV record.

        Adds notable + risk + correlation-search metadata so the detection
        plugs straight into Splunk Enterprise Security's Incident Review and
        Risk-Based Alerting framework — not just a raw scheduled search.
        """
        # Splunk caps saved-search names at 100 characters. The model
        # occasionally produces a long, descriptive title, so clamp it here and
        # use the clamped value everywhere downstream (saved search, ES
        # metadata, KV runbook) so they all agree.
        if len(doc.saved_search_name) > 100:
            doc.saved_search_name = doc.saved_search_name[:100].rstrip(" -–—")

        es_extras: dict[str, str | int] = {}
        if design is not None:
            es_extras = _es_kwargs(doc, design)
        name = self.splunk.create_saved_search(
            doc.saved_search_name, spl,
            description=doc.description,
            **es_extras,
        )
        # Report the mode the create actually landed in. If ES wasn't installed,
        # create_saved_search transparently retried without ES metadata and set
        # last_deploy_mode="plain" — so we never claim ES enrichment we didn't
        # actually apply.
        es_applied = getattr(self.splunk, "last_deploy_mode", None) == "es"
        self.splunk.kv_upsert(
            "counterspell_runbook",
            {
                "name": doc.saved_search_name,
                "description": doc.description,
                "mitre": ",".join(doc.mitre_techniques),
                "triage_steps": " | ".join(doc.triage_steps),
                "validation": doc.validation_summary,
                "spl": spl,
                "es_enabled": "true" if es_applied else "false",
            },
        )
        return name

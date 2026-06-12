"""ES (Enterprise Security) metadata stamped on every deployed saved search."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from counterspell.agents.deployer import Deployer, _es_kwargs, _risk_objects
from counterspell.schemas import DetectionDesign, DetectionDoc


def _design(**overrides) -> DetectionDesign:
    base = dict(
        title="Bulk Outbound Transfer to Single External IP",
        mitre_techniques=["T1048"],
        rationale="r",
        sourcetypes=["cs:network"],
        key_fields=["src_ip", "dest_ip", "dest_port"],
        logic="l",
        thresholds={},
        false_positive_notes="",
    )
    base.update(overrides)
    return DetectionDesign(**base)


def _doc() -> DetectionDoc:
    return DetectionDoc(
        saved_search_name="Counterspell - Bulk Outbound Transfer",
        description="Detects large outbound transfers to a single external IP.",
        mitre_techniques=["T1048"],
        triage_steps=["confirm IP not whitelisted", "check user activity"],
        validation_summary="caught attack with 0 FPs after 3 iterations",
    )


def test_risk_objects_built_from_key_fields():
    objs = _risk_objects(_design(key_fields=["user", "src_ip", "host", "irrelevant"]))
    types = sorted({o["risk_object_type"] for o in objs})
    fields = sorted({o["risk_object_field"] for o in objs})
    assert "user" in types
    assert "system" in types
    assert "user" in fields and "src_ip" in fields and "host" in fields
    assert all(o["risk_score"] >= 1 for o in objs)


def test_risk_objects_default_when_no_recognized_fields():
    objs = _risk_objects(_design(key_fields=["unknown_field"]))
    assert len(objs) == 1
    assert objs[0]["risk_object_type"] == "system"


def test_es_kwargs_contain_notable_and_risk_actions():
    kw = _es_kwargs(_doc(), _design())
    assert "notable" in kw["actions"]
    assert "risk" in kw["actions"]
    assert kw["action.notable"] == "1"
    assert kw["action.risk"] == "1"
    assert kw["action.correlationsearch.enabled"] == "1"
    # The rule_title is the saved-search name — what ES surfaces in Incident Review.
    assert "Counterspell" in kw["action.notable.param.rule_title"]


def test_es_kwargs_risk_param_is_json_serializable_list():
    kw = _es_kwargs(_doc(), _design())
    parsed = json.loads(kw["action.risk.param._risk"])
    assert isinstance(parsed, list) and parsed
    assert {"risk_object_field", "risk_object_type", "risk_score"} <= set(parsed[0].keys())


def test_deploy_passes_es_kwargs_to_saved_search_creation():
    splunk = MagicMock()
    splunk.create_saved_search.return_value = "Counterspell - Demo"
    # Simulate a real ES-capable instance: the create landed in "es" mode.
    splunk.last_deploy_mode = "es"
    llm = MagicMock()
    d = Deployer(llm, splunk)
    d.deploy(_doc(), 'search index="counterspell" ...', _design())

    call = splunk.create_saved_search.call_args
    kwargs = call.kwargs
    assert kwargs["action.notable"] == "1"
    assert kwargs["action.risk"] == "1"
    assert "_risk" in kwargs["action.risk.param._risk"] or kwargs["action.risk.param._risk"]
    # KV runbook records the ES flag for the dashboard.
    splunk.kv_upsert.assert_called_once()
    record = splunk.kv_upsert.call_args.args[1]
    assert record["es_enabled"] == "true"


def test_deploy_reports_plain_mode_when_es_absent():
    """When ES isn't installed, create_saved_search falls back to plain mode and
    the KV record must NOT claim ES enrichment — honesty over optimism."""
    splunk = MagicMock()
    splunk.create_saved_search.return_value = "Counterspell - Demo"
    splunk.last_deploy_mode = "plain"  # ES create was rejected, fell back
    llm = MagicMock()
    d = Deployer(llm, splunk)
    d.deploy(_doc(), 'search index="counterspell" ...', _design())

    record = splunk.kv_upsert.call_args.args[1]
    assert record["es_enabled"] == "false"


def test_deploy_without_design_skips_es_kwargs():
    """Backwards-compatible: old callers that don't pass design still work."""
    splunk = MagicMock()
    splunk.create_saved_search.return_value = "Counterspell - Demo"
    llm = MagicMock()
    d = Deployer(llm, splunk)
    d.deploy(_doc(), "spl")

    kwargs = splunk.create_saved_search.call_args.kwargs
    assert "action.notable" not in kwargs
    record = splunk.kv_upsert.call_args.args[1]
    assert record["es_enabled"] == "false"

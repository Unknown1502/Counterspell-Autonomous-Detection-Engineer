"""Red-team _repair contract: the generated attack must always be catchable.

These pin the seams the orchestrator depends on but the LLM does not
guarantee — the exact gaps that made the loop fail to converge for real:
  • a scenario_id always exists (TP attribution),
  • the attacker entity is on every event,
  • the design's key_fields exist on every event (the rule has something to fire on),
  • every event has a recent, in-window _time (the backtest range contains it).
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from counterspell.agents.redteam import RedTeam
from counterspell.schemas import AttackEvent, AttackScenario, DetectionDesign


def _design(**overrides) -> DetectionDesign:
    base = dict(
        title="Bulk Outbound Transfer",
        mitre_techniques=["T1048"],
        rationale="r",
        sourcetypes=["cs:network"],
        key_fields=["src_ip", "dest_ip", "bytes_out", "dest_port"],
        logic="large outbound transfer to one external IP",
        thresholds={},
        false_positive_notes="",
    )
    base.update(overrides)
    return DetectionDesign(**base)


def _redteam_returning(scenario: AttackScenario) -> RedTeam:
    llm = MagicMock()
    llm.complete_json.return_value = scenario
    return RedTeam(llm, MagicMock())


def test_repair_fills_missing_scenario_id():
    scen = AttackScenario(scenario_id="", attacker={"src_ip": "10.66.66.66"},
                          window={}, events=[AttackEvent(sourcetype="cs:network", fields={})])
    out = _redteam_returning(scen).generate(_design())
    assert out.scenario_id and out.scenario_id.strip()


def test_repair_injects_attacker_when_empty():
    scen = AttackScenario(scenario_id="s1", attacker={}, window={},
                          events=[AttackEvent(sourcetype="cs:network", fields={})])
    out = _redteam_returning(scen).generate(_design())
    assert out.attacker  # at least one concrete entity
    # And the attacker is stamped on every event.
    for ev in out.events:
        assert any(out.attacker.get(k) == ev.fields.get(k) for k in out.attacker)


def test_repair_ensures_key_fields_present_on_events():
    """The model omitted bytes_out; repair must add it so the rule can fire."""
    scen = AttackScenario(
        scenario_id="s1",
        attacker={"src_ip": "10.66.66.66"},
        window={},
        events=[AttackEvent(sourcetype="cs:network", fields={"src_ip": "10.66.66.66"})],
    )
    out = _redteam_returning(scen).generate(_design())
    for ev in out.events:
        for kf in _design().key_fields:
            assert kf in ev.fields, f"key field {kf} missing from attack event"


def test_repair_stamps_recent_in_window_time():
    scen = AttackScenario(
        scenario_id="s1",
        attacker={"src_ip": "10.66.66.66"},
        window={},
        events=[AttackEvent(sourcetype="cs:network", fields={"_time": "1999-01-01T00:00:00Z"})],
    )
    out = _redteam_returning(scen).generate(_design())
    now = datetime.now(timezone.utc)
    for ev in out.events:
        ts = datetime.fromisoformat(str(ev.fields["_time"]).replace("Z", "+00:00"))
        age_hours = (now - ts).total_seconds() / 3600
        assert 0 <= age_hours < 24, "attack event must be recent and in-window"


def test_repair_synthesizes_events_when_model_returns_none():
    scen = AttackScenario(scenario_id="s1", attacker={"src_ip": "10.66.66.66"},
                          window={}, events=[])
    out = _redteam_returning(scen).generate(_design())
    assert len(out.events) >= 1
    assert out.events[0].sourcetype == "cs:network"

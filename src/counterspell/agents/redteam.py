"""Red-team agent: generates synthetic attack events and injects them via Splunk HEC."""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

from .. import prompts
from ..llm_client import LLMClient
from ..schemas import AttackEvent, AttackScenario, DetectionDesign
from ..splunk_client import SplunkClient

log = logging.getLogger(__name__)


class RedTeam:
    """Generates synthetic attack scenarios and injects them into Splunk via HEC."""

    def __init__(self, llm: LLMClient, splunk: SplunkClient) -> None:
        self.llm = llm
        self.splunk = splunk

    def generate(self, design: DetectionDesign) -> AttackScenario:
        """Produce a small synthetic attack scenario matching the design's MITRE technique.

        The raw LLM output is not trusted as-is. `_repair` enforces the
        contract the rest of the loop depends on:
          • a unique, lowercase scenario_id (so TP attribution is unambiguous);
          • at least one concrete attacker entity;
          • every event tagged with the design's primary sourcetype;
          • every event carrying the attacker entity + the design's key_fields,
            so the detection actually has something to fire on;
          • a recent, in-window `_time` on every event, so the backtest's
            `-31d..now` range always contains the injected attack.
        Without this repair, a model that omits `bytes_out` (or stamps a
        future timestamp) produces a scenario the detection can never catch,
        and the loop runs to the iteration cap reporting `incomplete`.
        """
        prompt = prompts.REDTEAM_GENERATE.format(
            shared=prompts.SHARED_CONTEXT,
            mitre_techniques=json.dumps(design.mitre_techniques),
            logic=design.logic,
        )
        scenario = self.llm.complete_json(prompt, AttackScenario, temperature=0.5)
        return self._repair(scenario, design)

    def _repair(
        self, scenario: AttackScenario, design: DetectionDesign
    ) -> AttackScenario:
        # 1. Unambiguous scenario id.
        sid = (scenario.scenario_id or "").strip().lower()
        if not sid:
            sid = f"cs-{uuid.uuid4().hex[:10]}"
        scenario.scenario_id = sid

        # 2. Guarantee at least one concrete attacker entity.
        attacker = {k: str(v) for k, v in (scenario.attacker or {}).items() if v}
        if not attacker:
            attacker = {"src_ip": "10.66.66.66", "user": "cs_attacker",
                        "host": "cs-attacker-host"}
        scenario.attacker = attacker

        # 3. Primary sourcetype the detection actually reads.
        primary_st = (design.sourcetypes or ["cs:auth"])[0]

        # 4. Spread events across a recent, definitely-in-window span.
        now = datetime.now(timezone.utc)
        events = scenario.events or []
        if not events:
            # Model returned no events — synthesize a minimal burst so the
            # detection has a true positive to find.
            events = [AttackEvent(sourcetype=primary_st, fields={}) for _ in range(8)]

        repaired: list[AttackEvent] = []
        n = len(events)
        for i, ev in enumerate(events):
            fields = dict(ev.fields or {})
            # Attacker entity present on every event.
            fields.update(attacker)
            # The design's key fields must exist so the detection can match.
            for kf in (design.key_fields or []):
                fields.setdefault(kf, self._default_for_field(kf, attacker))
            # Recent, monotonically-spaced timestamp inside the backtest window.
            ts = now - timedelta(minutes=(n - i) * 2)
            fields["_time"] = ts.isoformat()
            repaired.append(AttackEvent(sourcetype=ev.sourcetype or primary_st,
                                        fields=fields))
        scenario.events = repaired
        scenario.window = {
            "earliest": (now - timedelta(minutes=n * 2 + 5)).isoformat(),
            "latest": now.isoformat(),
        }
        return scenario

    @staticmethod
    def _default_for_field(field: str, attacker: dict[str, str]) -> object:
        """Provide a plausible attack-shaped value for a key field the model omitted."""
        if field in attacker:
            return attacker[field]
        f = field.lower()
        if "byte" in f:
            return 500 * 1024 * 1024  # large transfer — trips exfil/volume rules
        if "count" in f or "attempt" in f or "fail" in f:
            return 50  # high count — trips brute-force/burst rules
        if "port" in f:
            return 4444  # classic non-standard port
        if f in ("action",):
            return "failure"
        if "cmd" in f or "command" in f or "process" in f:
            return "powershell.exe -NoP -W Hidden -EncodedCommand QQBhAGEA"
        return "cs_attack"

    def inject(self, scenario: AttackScenario) -> int:
        """Send the scenario's events to Splunk HEC and return the count injected.

        After injecting, give Splunk a short, bounded window to make the
        events searchable. HEC indexing is near-real-time but not instant on a
        cold trial instance; without a settle pause the very first backtest can
        run before the attack is queryable and wrongly report `tp_caught=False`.
        """
        events = [e.model_dump() for e in scenario.events]
        count = self.splunk.inject_via_hec(events, scenario.scenario_id)
        self._wait_until_searchable(scenario)
        return count

    def _wait_until_searchable(
        self, scenario: AttackScenario, *, attempts: int = 6, interval: float = 2.0
    ) -> None:
        """Poll until the injected scenario is queryable, or give up gracefully.

        Uses a cheap count search keyed on cs_scenario_id. Best-effort: a
        failure here (MCP/SDK hiccup) must not block the run — we just proceed
        and let the normal backtest+retry loop handle it.
        """
        sid = scenario.scenario_id
        probe = (
            f'search index="counterspell" cs_scenario_id="{sid}" '
            "earliest=-1h latest=now | stats count"
        )
        for attempt in range(attempts):
            try:
                rows = self.splunk.oneshot(probe, earliest="-1h", latest="now")
                total = 0
                for r in rows:
                    try:
                        total += int(r.get("count", 0))
                    except (TypeError, ValueError):
                        continue
                if total > 0:
                    log.info("scenario %s searchable after %.1fs",
                             sid, attempt * interval)
                    return
            except Exception as e:  # noqa: BLE001 — settle is best-effort.
                log.debug("searchable-probe attempt %d failed: %s", attempt + 1, e)
            time.sleep(interval)
        log.warning("scenario %s not confirmed searchable after %.1fs; proceeding",
                    sid, attempts * interval)

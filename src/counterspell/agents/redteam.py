"""Red-team agent: generates synthetic attack events and injects them via Splunk HEC."""

from __future__ import annotations

import ipaddress
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

        # 3b. Exfil / C2 originates FROM an internal host. Keep the model's
        #     src_ip only if it is already internal; otherwise pin it to an
        #     internal address so the attack matches how the detection is
        #     written (internal source -> external destination).
        if not self._is_private(str(attacker.get("src_ip", ""))):
            attacker["src_ip"] = "10.0.0.66"
        scenario.attacker = attacker

        now = datetime.now(timezone.utc)
        events = list(scenario.events or [])

        # 4. Build a CONCENTRATED, coherent burst. A real attack repeats: the
        #    same internal source hits the same external destination/port many
        #    times. That clusterable signal is exactly what separates the attack
        #    from the scattered, one-off benign large transfers in the baseline,
        #    so a tuned rule can keep the attack while shedding the noise.
        def _coherent(fields: dict) -> dict:
            fields.update(attacker)
            for kf in (design.key_fields or []):
                fields.setdefault(kf, self._default_for_field(kf, attacker))
            if primary_st == "cs:network":
                fields["dest_ip"] = self._EXTERNAL_DEST
                fields["dest_port"] = self._NONSTANDARD_PORT
                fields["protocol"] = "tcp"
                fields["bytes_out"] = self._BURST_BYTES
            else:
                # Keep the attack off standard service ports for non-network
                # techniques that still carry a port field.
                self._force_nonstandard_port(fields)
            return fields

        repaired: list[AttackEvent] = []
        for ev in events:
            st = ev.sourcetype or primary_st
            base = dict(ev.fields or {})
            fields = _coherent(base) if st == primary_st else {**base, **attacker}
            repaired.append(AttackEvent(sourcetype=st, fields=fields))

        # Guarantee enough PRIMARY-sourcetype events that any per-entity
        # aggregation sees a cluster, even if the model emitted only a handful.
        primary_count = sum(1 for e in repaired if e.sourcetype == primary_st)
        for _ in range(max(0, self._MIN_BURST - primary_count)):
            repaired.append(AttackEvent(sourcetype=primary_st, fields=_coherent({})))

        # Recent, monotonically-spaced timestamps inside the backtest window.
        n = len(repaired)
        for i, ev in enumerate(repaired):
            ev.fields["_time"] = (now - timedelta(minutes=(n - i) * 2)).isoformat()

        scenario.events = repaired
        scenario.window = {
            "earliest": (now - timedelta(minutes=n * 2 + 5)).isoformat(),
            "latest": now.isoformat(),
        }
        return scenario

    # The RFC1918 ranges detection rules actually test with cidrmatch. We match
    # these exactly (not ipaddress.is_private, which also counts TEST-NET/doc
    # ranges as private and would let a non-RFC1918 src slip through).
    _RFC1918 = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]

    @classmethod
    def _is_private(cls, ip: str) -> bool:
        """True if ip is RFC1918 internal — what a cidrmatch detection treats as inside."""
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        return any(addr in net for net in cls._RFC1918)

    # Ports a detection would reasonably treat as benign / standard service
    # traffic. A red-team event sitting on one of these is self-defeating.
    _STANDARD_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445,
                       465, 587, 993, 995, 3389}
    _NONSTANDARD_PORT = 4444
    # Fixed external target for the exfil burst (TEST-NET-3, non-private).
    _EXTERNAL_DEST = "203.0.113.77"
    _BURST_BYTES = 250 * 1024 * 1024  # 250 MB per event — unambiguously large
    _MIN_BURST = 15  # enough repeats to clearly clear the benign noise floor

    @classmethod
    def _force_nonstandard_port(cls, fields: dict) -> None:
        """Move any port-named field off a standard port onto a non-standard one."""
        for key in list(fields.keys()):
            if "port" not in key.lower():
                continue
            try:
                port = int(str(fields[key]).strip())
            except (TypeError, ValueError):
                continue
            if port in cls._STANDARD_PORTS:
                fields[key] = cls._NONSTANDARD_PORT

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

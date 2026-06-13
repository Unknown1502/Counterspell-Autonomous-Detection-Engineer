"""Thin Splunk client wrapping the official SDK for searches, HEC, saved searches, and KV store."""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime
from typing import Any

import requests
import splunklib.client as splunk_client
import splunklib.results as splunk_results
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


def _to_epoch(value: Any) -> float | None:
    """Best-effort convert a _time value (ISO8601 string or epoch) to epoch seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if not s:
        return None
    try:
        return float(s)  # already epoch-as-string
    except ValueError:
        pass
    try:
        # Accept trailing 'Z' (Python <3.11 fromisoformat rejects it).
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        log.debug("could not parse _time %r as epoch", value)
        return None


class SplunkClient:
    """Wrapper around splunklib for searches, HEC injection, saved-search creation, and KV upserts."""

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        hec_url: str,
        hec_token: str,
        index: str,
    ) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.hec_url = hec_url
        self.hec_token = hec_token
        self.index = index
        self.last_deploy_mode: str | None = None  # "es" | "plain" after a create
        self.service = splunk_client.connect(
            host=host,
            port=port,
            splunkToken=token,
            scheme="https",
            verify=False,
        )

    def oneshot(
        self, spl: str, earliest: str = "-30d", latest: str = "now"
    ) -> list[dict[str, Any]]:
        """Run a blocking one-shot search and return result rows as dicts."""
        kwargs = {
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
        }
        body = self.service.jobs.oneshot(spl, **kwargs)
        if isinstance(body, (bytes, bytearray)):
            stream = io.BytesIO(body)
        else:
            stream = body
        reader = splunk_results.JSONResultsReader(stream)
        rows: list[dict[str, Any]] = []
        for item in reader:
            if isinstance(item, dict):
                rows.append(item)
        return rows

    def inject_via_hec(self, events: list[dict[str, Any]], scenario_id: str) -> int:
        """POST events to Splunk HEC, stamping cs_scenario_id on each event."""
        if not events:
            return 0
        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }
        payload_lines: list[str] = []
        for ev in events:
            sourcetype = ev.get("sourcetype", "cs:auth")
            fields = dict(ev.get("fields") or {})
            fields["cs_scenario_id"] = scenario_id
            envelope: dict[str, Any] = {
                "event": fields,
                "sourcetype": sourcetype,
                "index": self.index,
            }
            # Honor an explicit per-event timestamp by promoting it to the HEC
            # envelope `time` (epoch seconds). Without this, HEC stamps the
            # event at receive-time and the red-team's carefully-windowed
            # timestamps are ignored — which can push events outside the
            # backtest range or scramble their order.
            epoch = _to_epoch(fields.get("_time"))
            if epoch is not None:
                envelope["time"] = epoch
            payload_lines.append(json.dumps(envelope, default=str))
        body = "\n".join(payload_lines)
        try:
            resp = requests.post(
                self.hec_url, headers=headers, data=body, verify=False, timeout=30
            )
            if 200 <= resp.status_code < 300:
                return len(events)
            log.warning(
                "HEC inject failed (%s): %s — falling back to REST receivers",
                resp.status_code, resp.text[:200],
            )
        except requests.RequestException as e:
            log.warning("HEC unreachable (%s) — falling back to REST receivers", e)
        envelopes = [json.loads(line) for line in payload_lines]
        return self.ingest_via_rest(envelopes)

    def ingest_via_rest(self, envelopes: list[dict[str, Any]]) -> int:
        """Fallback ingestion when HEC is down: POST raw JSON lines to the
        `receivers/simple` endpoint over the management port.

        Each line is exactly the JSON `event` payload HEC's /event endpoint
        would have indexed, so `_raw` and search-time field extraction
        (cs_scenario_id, cs_holdout, ...) are identical to the HEC path.
        Timestamps are parsed from the leading `_time` key of each JSON line
        by Splunk's automatic ISO8601 detection (verified: backfilled events
        land at their historical _time, not receive-time).
        """
        by_st: dict[str, list[str]] = {}
        for env in envelopes:
            st = env.get("sourcetype", "cs:auth")
            by_st.setdefault(st, []).append(
                json.dumps(env.get("event") or {}, default=str)
            )
        url = f"https://{self.host}:{self.port}/services/receivers/simple"
        headers = {"Authorization": f"Bearer {self.token}"}
        total = 0
        for st, lines in by_st.items():
            resp = requests.post(
                url,
                params={"index": self.index, "sourcetype": st},
                headers=headers,
                data="\n".join(lines) + "\n",
                verify=False,
                timeout=60,
            )
            if not (200 <= resp.status_code < 300):
                raise RuntimeError(
                    f"REST ingest fallback failed ({resp.status_code}): "
                    f"{resp.text[:300]}"
                )
            total += len(lines)
        return total

    def has_enterprise_security(self) -> bool:
        """True if Splunk Enterprise Security (the SplunkEnterpriseSecuritySuite app) is installed.

        The ES-specific modular actions (notable, risk, correlationsearch) only
        exist when ES is present. On a vanilla Enterprise trial they are
        unknown keys and `saved_searches.create` may reject them. We probe once
        so deploy can choose full-ES vs. plain-scheduled metadata.
        """
        try:
            apps = {a.name.lower() for a in self.service.apps}
        except Exception as e:  # noqa: BLE001
            log.warning("Could not list apps to detect ES: %s", e)
            return False
        return any(
            a in apps
            for a in ("splunkenterprisesecuritysuite", "enterprisesecurity",
                      "splunk_app_es", "es")
        )

    def create_saved_search(self, name: str, spl: str, **kwargs: Any) -> str:
        """Create (or recreate) a saved search and return its name.

        We only attach ES/RBA metadata when Enterprise Security is ACTUALLY
        installed. A stock Splunk silently accepts the `action.notable`/`risk`
        keys as inert settings, so trusting "the create succeeded" would let us
        claim ES enrichment that nothing can act on. We probe for ES first and
        report `last_deploy_mode` honestly: "es" only when ES is present,
        "plain" otherwise. Deploy never fails for lack of ES — the detection
        still ships as a real scheduled saved search.
        """
        base: dict[str, Any] = {
            "dispatch.earliest_time": "-24h",
            "dispatch.latest_time": "now",
            "is_scheduled": 1,
            "cron_schedule": "*/15 * * * *",
            "alert.track": 1,
        }
        full = {**base, **kwargs}

        try:
            if name in self.service.saved_searches:
                self.service.saved_searches.delete(name)
        except Exception as e:  # noqa: BLE001
            log.warning("Could not delete existing saved search %s: %s", name, e)

        es_present = bool(kwargs) and self.has_enterprise_security()
        if es_present:
            try:
                self.service.saved_searches.create(name, spl, **full)
                self.last_deploy_mode = "es"
                return name
            except Exception as e:  # noqa: BLE001
                log.warning(
                    "ES saved-search create failed (%s); shipping plain "
                    "scheduled search instead.", e,
                )
                try:
                    if name in self.service.saved_searches:
                        self.service.saved_searches.delete(name)
                except Exception:  # noqa: BLE001
                    pass

        # No ES (or ES create failed): drop ES-only keys, ship the core
        # scheduled search. This is the honest "ES-ready" path.
        plain = {
            k: v for k, v in full.items()
            if not (k.startswith("action.") or k.startswith("actions")
                    or k.startswith("request."))
        }
        # Re-delete in case a partial object was created on the first attempt.
        try:
            if name in self.service.saved_searches:
                self.service.saved_searches.delete(name)
        except Exception:  # noqa: BLE001
            pass
        self.service.saved_searches.create(name, spl, **plain)
        self.last_deploy_mode = "plain"
        return name

    def list_counterspell_runbook(self) -> list[dict[str, Any]]:
        """Read every record from the counterspell_runbook KV collection.

        Used by the deduplication check in the Orchestrator to avoid
        re-designing a detection for a MITRE technique that already has a
        Counterspell-deployed saved search.
        """
        app_ns = self.service.namespace
        owner = getattr(app_ns, "owner", "nobody") or "nobody"
        app = getattr(app_ns, "app", "search") or "search"
        url = (
            f"https://{self.host}:{self.port}/servicesNS/{owner}/{app}/"
            "storage/collections/data/counterspell_runbook"
        )
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            resp = requests.get(url, headers=headers, verify=False, timeout=15)
            if 200 <= resp.status_code < 300:
                data = resp.json()
                return data if isinstance(data, list) else []
        except Exception as e:  # noqa: BLE001
            log.warning("KV read failed: %s", e)
        return []

    def kv_upsert(self, collection: str, record: dict[str, Any]) -> None:
        """Create the KV collection if missing, then insert a record.

        The collection normally ships with the Counterspell app
        (collections.conf), but the CLI demo runs against a stock `search` app
        where it does not exist yet. We ensure it via the REST config endpoint
        (idempotent: 409 means it already exists) so a deploy is self-contained
        and reproducible on a fresh Splunk, rather than depending on the SDK
        kvstore object's app context.
        """
        app_ns = self.service.namespace
        owner = getattr(app_ns, "owner", "nobody") or "nobody"
        app = getattr(app_ns, "app", "search") or "search"
        ns = f"https://{self.host}:{self.port}/servicesNS/{owner}/{app}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        ensure = requests.post(
            f"{ns}/storage/collections/config",
            headers={"Authorization": f"Bearer {self.token}"},
            data={"name": collection},
            verify=False,
            timeout=30,
        )
        if ensure.status_code not in (200, 201, 409):
            log.warning(
                "KV collection ensure failed (%s): %s",
                ensure.status_code, ensure.text[:300],
            )

        resp = requests.post(
            f"{ns}/storage/collections/data/{collection}",
            headers=headers,
            data=json.dumps(record),
            verify=False,
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            log.warning(
                "KV upsert failed (%s): %s", resp.status_code, resp.text[:300]
            )

"""Validator agent: backtests SPL against Splunk and separates TPs from FPs."""

from __future__ import annotations

import logging
import re
from typing import Any

from ..mcp_client import MCPClient
from ..schemas import AttackScenario, ValidationResult

log = logging.getLogger(__name__)


class Validator:
    """Runs SPL via MCP/SDK, then classifies each hit as a TP or FP using attacker markers."""

    def __init__(self, mcp: MCPClient) -> None:
        self.mcp = mcp

    def backtest(
        self, iteration: int, spl: str, scenario: AttackScenario
    ) -> ValidationResult:
        """Run the SPL search and return a ValidationResult for this iteration.

        A search that fails to execute (malformed SPL from the LLM, an
        invalid field reference, a search-quota error) must NEVER crash the
        run mid-demo. We convert any execution failure into a recoverable
        result: the true positive is reported as not caught and the SPL is
        annotated, which lets the tune loop produce a corrected design on the
        next iteration instead of dumping a traceback on screen.
        """
        try:
            rows = self.mcp.run_query(spl, earliest="-31d", latest="now")
        except Exception as e:  # noqa: BLE001 — a bad search must not kill the demo.
            log.warning("backtest iter %d: SPL failed to execute: %s", iteration, e)
            return ValidationResult(
                iteration=iteration,
                spl=spl,
                tp_caught=False,
                fp_count=0,
                sample_fps=[],
                error=str(e)[:300],
            )
        tp_rows, fp_rows = self._split(rows, scenario)
        # The holdout generalization set (cs_holdout=true) is never counted as a
        # tuning FP and never shown to the Architect — the tuning loop tunes
        # against the PRIMARY noise only. After convergence,
        # scripts/check_generalization.py separately asserts the deployed rule
        # fires on zero holdout rows. Keeping holdout out of the tuning signal
        # is what makes that a genuine generalization test, not a memorization.
        tuning_fps = [r for r in fp_rows if not self._is_holdout(r)]
        return ValidationResult(
            iteration=iteration,
            spl=spl,
            tp_caught=len(tp_rows) >= 1,
            fp_count=len(tuning_fps),
            sample_fps=tuning_fps[:5],
        )

    @staticmethod
    def _is_holdout(row: dict[str, Any]) -> bool:
        """True if a result row carries the holdout marker (cs_holdout=true)."""
        for key in ("cs_holdout", "holdout"):
            val = row.get(key)
            if val is None:
                continue
            if str(val).strip().lower() in ("true", "1", "yes"):
                return True
        return False

    def _split(
        self, rows: list[dict[str, Any]], scenario: AttackScenario
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Partition rows into (true_positives, false_positives) using attacker markers.

        Classification is value-exact, not substring-anywhere. The previous
        approach stringified the whole row and checked whether a marker
        appeared *anywhere* in the blob — that let a benign `count=99` row
        match an attacker IP ending in `99`, inflating TPs and hiding FPs.

        We now match markers against individual field *values*:
          1. The strongest marker is `cs_scenario_id`: every red-team event is
             stamped with it at HEC inject time, and the red-team prompt is
             told to carry it through aggregation. An exact field match here
             is an unambiguous true positive.
          2. If `cs_scenario_id` survives nowhere (e.g. the LLM's SPL dropped
             it during `stats`), we fall back to exact matches on the attacker
             entity fields (`user`, `src_ip`, `host`) — but only when the row
             actually has a same-named field whose value equals the marker, or
             when the marker appears as a whole token in a multi-value field
             (e.g. a `values(src_ip)` list). No substring matching on counts.
        """
        sid = (scenario.scenario_id or "").strip().lower()
        entity_markers = {
            key: (scenario.attacker.get(key) or "").strip().lower()
            for key in ("user", "src_ip", "host")
            if (scenario.attacker.get(key) or "").strip()
        }

        tp_rows: list[dict[str, Any]] = []
        fp_rows: list[dict[str, Any]] = []
        for row in rows:
            if self._row_is_tp(row, sid, entity_markers):
                tp_rows.append(row)
            else:
                fp_rows.append(row)
        return tp_rows, fp_rows

    @staticmethod
    def _field_tokens(value: Any) -> set[str]:
        """Normalize one field value into a set of comparable lowercase tokens.

        Splunk multi-value fields arrive as a list, or as a single newline- or
        comma-joined string (e.g. from `values()`/`mvjoin`). We split on those
        delimiters so an attacker IP inside a `values(src_ip)` cell matches as
        a whole token, but a `count` of 4799 never matches the IP `...99`.
        """
        if value is None:
            return set()
        if isinstance(value, (list, tuple, set)):
            parts = [str(v) for v in value]
        else:
            parts = re.split(r"[\s,;|]+", str(value))
        return {p.strip().lower() for p in parts if p.strip()}

    def _row_is_tp(
        self,
        row: dict[str, Any],
        sid: str,
        entity_markers: dict[str, str],
    ) -> bool:
        # 1. Strongest signal: the scenario id survived as a field value.
        if sid:
            for value in row.values():
                if sid in self._field_tokens(value):
                    return True
            # Also accept a literal cs_scenario_id column even if empty-ish.
            if sid in self._field_tokens(row.get("cs_scenario_id")):
                return True

        # 2. Fall back to exact attacker-entity field matches.
        for field, marker in entity_markers.items():
            if marker in self._field_tokens(row.get(field)):
                return True
            # The detection may rename the entity (e.g. `entity`, `src`).
            for value in row.values():
                if marker in self._field_tokens(value):
                    return True
        return False

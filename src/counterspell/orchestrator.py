"""Orchestrator: drives the five-agent loop from threat text to deployed saved search."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from .agents import Architect, Deployer, RedTeam, Translator, Validator
from .config import Config
from .llm_client import LLMClient
from .mcp_client import MCPClient
from .schemas import RunState
from .splunk_client import SplunkClient


def _confirm(state: RunState, last: Any = None) -> bool:
    """Print the proposed detection and ask the human whether to deploy."""
    last_iter = last or (state.iterations[-1] if state.iterations else None)
    title = state.design.title if state.design else "(no title)"
    spl = last_iter.spl if last_iter else "(no SPL)"
    tp = last_iter.tp_caught if last_iter else False
    print()
    print("=" * 70)
    print(f"Detection: {title}")
    print("-" * 70)
    print(f"SPL:\n{spl}")
    print("-" * 70)
    print(f"FP curve: {state.fp_curve}")
    print(f"True positive caught: {tp}")
    print("=" * 70)
    answer = input("Deploy this saved search to Splunk? [y/N] ")
    return answer.strip().lower() == "y"


class Orchestrator:
    """Coordinates all five Counterspell agents through the design-validate-deploy loop."""

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or Config.load()
        self.llm = LLMClient(
            base_url=self.cfg.llm_base_url,
            api_key=self.cfg.llm_api_key,
            model=self.cfg.llm_model,
        )
        self.splunk = SplunkClient(
            host=self.cfg.splunk_host,
            port=self.cfg.splunk_port,
            token=self.cfg.splunk_token,
            hec_url=self.cfg.hec_url,
            hec_token=self.cfg.hec_token,
            index=self.cfg.index,
        )
        self.mcp = MCPClient(
            mcp_url=self.cfg.mcp_url,
            mcp_token=self.cfg.mcp_token,
            fallback=self.splunk,
        )
        self.architect = Architect(self.llm)
        self.translator = Translator(self.llm, self.mcp)
        self.redteam = RedTeam(self.llm, self.splunk)
        self.validator = Validator(self.mcp)
        self.deployer = Deployer(self.llm, self.splunk)

    def run(
        self,
        threat_text: str,
        *,
        auto_approve: bool = False,
        on_event: Callable[[str, Any], None] | None = None,
        runs_dir: Path | str | None = None,
    ) -> RunState:
        """Run the full Counterspell loop and return the final RunState.

        If `runs_dir` is provided (default: <repo>/runs), the final RunState
        is appended as one JSON line to runs/<YYYY-MM-DD>.jsonl. These logs
        feed `scripts/export_navigator_layer.py` and the multi-threat
        coverage report.
        """
        emit = on_event or (lambda stage, payload: None)
        state = RunState(threat_text=threat_text)

        emit("design", None)
        state.design = self.architect.design(threat_text)

        existing = self._existing_coverage(state.design.mitre_techniques)
        if existing:
            emit("duplicate", existing)

        emit("redteam", state.design)
        state.scenario = self.redteam.generate(state.design)
        self.redteam.inject(state.scenario)

        # Track the best (TP-caught, lowest-FP) design+result seen so far, so
        # convergence is monotonic: we never deploy a worse rule than one we
        # already found, and we can stop early when tuning stops helping.
        best_result: Any = None
        best_design = state.design
        for i in range(1, self.cfg.max_iters + 1):
            emit("translate", i)
            spl = self.translator.to_spl(state.design)

            emit("validate", i)
            result = self.validator.backtest(i, spl, state.scenario)
            state.iterations.append(result)
            emit("result", result)

            if result.tp_caught and self._is_better(result, best_result):
                best_result = result
                best_design = state.design

            # Hard success: caught the attack and FPs within the budget.
            if result.tp_caught and result.fp_count <= self.cfg.fp_threshold:
                break

            # Last iteration — no point tuning a design we won't re-validate.
            if i == self.cfg.max_iters:
                break

            emit("tune", i)
            state.design = self.architect.tune(state.design, spl, result)

        # Promote the best design/result so deploy + approval use the lowest-FP
        # rule we actually achieved, not merely the final iteration.
        if best_result is not None:
            state.design = best_design

        converged = best_result is not None and (
            best_result.fp_count <= self.cfg.fp_threshold
            or self.cfg.allow_best_effort
        )
        if not converged:
            emit("incomplete", state.fp_curve)
            self._persist_run(state, runs_dir, outcome="incomplete")
            return state

        if not auto_approve:
            if not _confirm(state, best_result):
                emit("declined", None)
                self._persist_run(state, runs_dir, outcome="declined")
                return state

        emit("deploy", None)
        best = best_result
        doc = self.deployer.document(
            state.design,
            best.spl,
            best.tp_caught,
            best.fp_count,
            len(state.iterations),
        )
        state.doc = doc
        state.deployed_name = self.deployer.deploy(doc, best.spl, state.design)
        emit("deployed", state.deployed_name)
        self._persist_run(state, runs_dir, outcome="deployed")
        return state

    @staticmethod
    def _is_better(candidate: Any, incumbent: Any) -> bool:
        """True if candidate is a strictly better backtest result than incumbent.

        Both are assumed TP-caught. Fewer false positives wins; ties keep the
        incumbent (earlier-found) so the curve reads as monotonic improvement.
        """
        if incumbent is None:
            return True
        return candidate.fp_count < incumbent.fp_count

    def _existing_coverage(self, mitre_techniques: list[str]) -> list[dict[str, Any]]:
        """Return any prior Counterspell deployments that cover these techniques.

        Non-blocking: the loop still runs to allow tightening or re-tuning,
        but the result is emitted so the dashboard/CLI can flag the overlap.
        """
        if not mitre_techniques:
            return []
        try:
            records = self.splunk.list_counterspell_runbook()
        except Exception:  # noqa: BLE001
            return []
        wanted = {t.strip().upper() for t in mitre_techniques if t}
        hits: list[dict[str, Any]] = []
        for rec in records:
            tags = (rec.get("mitre") or "").upper().replace(" ", "")
            if not tags:
                continue
            rec_techs = {t for t in tags.split(",") if t}
            overlap = wanted & rec_techs
            if overlap:
                hits.append({
                    "name": rec.get("name"),
                    "covers": sorted(overlap),
                    "description": rec.get("description"),
                })
        return hits

    def _persist_run(
        self,
        state: RunState,
        runs_dir: Path | str | None,
        *,
        outcome: str,
    ) -> Path | None:
        """Append one JSON line to runs/<YYYY-MM-DD>.jsonl. Never raises."""
        try:
            base = Path(runs_dir) if runs_dir else Path(__file__).resolve().parents[2] / "runs"
            base.mkdir(parents=True, exist_ok=True)
            day = time.strftime("%Y-%m-%d", time.gmtime())
            path = base / f"{day}.jsonl"
            mcp = getattr(self, "mcp", None)
            splunk = getattr(self, "splunk", None)
            record = {
                "ts": time.time(),
                "outcome": outcome,
                # Provenance proof: did MCP genuinely serve any call this run, or
                # did everything fall back to the SDK? Lets you substantiate the
                # "uses Splunk MCP Server" claim from the run log, not just hope.
                "used_mcp": getattr(mcp, "used_mcp", False),
                "deploy_mode": getattr(splunk, "last_deploy_mode", None),
                "state": json.loads(state.model_dump_json()),
            }
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
            return path
        except Exception:  # noqa: BLE001 — persistence is best-effort.
            return None

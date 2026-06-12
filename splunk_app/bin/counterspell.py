#!/usr/bin/env python3
"""Splunk custom search command wrapping the Counterspell orchestrator.

Usage from the Splunk search bar:

    | counterspell threat="threats/t1048_exfil.md"
    | counterspell threat_text="An attacker is exfiltrating data..."
    | counterspell threat="threats/t1110_bruteforce.md" auto_approve=true

Each progress event from the orchestrator is emitted as one result row so
the Counterspell dashboard can render the run live.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any

APP_BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_BIN))

# Splunk ships splunklib with every install; importable from $SPLUNK_HOME/lib/python*/.
from splunklib.searchcommands import (  # noqa: E402
    Configuration,
    GeneratingCommand,
    Option,
    dispatch,
    validators,
)


def _resolve_runtime() -> None:
    """Make `import counterspell` work from inside the Splunk app sandbox."""
    home = os.environ.get("COUNTERSPELL_HOME")
    if home:
        src = Path(home) / "src"
        if src.is_dir():
            sys.path.insert(0, str(src))
            return
    # Fallback: assume the app is installed as a sibling of the repo root.
    repo_guess = APP_BIN.parents[2]
    src = repo_guess / "src"
    if src.is_dir():
        sys.path.insert(0, str(src))


@Configuration(type="reporting")
class CounterspellCommand(GeneratingCommand):
    """Runs the Counterspell loop and streams progress as result rows."""

    threat = Option(
        doc="Path to a threat markdown file (relative to COUNTERSPELL_HOME).",
        require=False,
    )
    threat_text = Option(
        doc="Inline threat description. Mutually exclusive with `threat`.",
        require=False,
    )
    auto_approve = Option(
        doc="Skip the human approval gate. Default false.",
        require=False,
        default=False,
        validate=validators.Boolean(),
    )

    def _load_threat(self) -> str:
        if self.threat_text:
            return str(self.threat_text)
        if not self.threat:
            raise ValueError("Provide either threat=<path> or threat_text=<string>.")
        home = os.environ.get("COUNTERSPELL_HOME", "")
        candidate = Path(self.threat)
        if not candidate.is_absolute() and home:
            candidate = Path(home) / candidate
        return candidate.read_text(encoding="utf-8")

    def _row(self, stage: str, message: str, **extra: Any) -> dict[str, Any]:
        row = {
            "_time": time.time(),
            "stage": stage,
            "message": message,
        }
        for k, v in extra.items():
            if v is None:
                continue
            if isinstance(v, (dict, list)):
                row[k] = json.dumps(v, default=str)
            else:
                row[k] = v
        return row

    def generate(self):  # noqa: D401 — required by SearchCommand contract.
        """Stream one row per stage; final row is the run summary."""
        try:
            _resolve_runtime()
            from counterspell import Orchestrator  # type: ignore
            from counterspell.schemas import ValidationResult  # type: ignore

            threat_text = self._load_threat()
            yield self._row("start", "Counterspell run beginning",
                            chars=len(threat_text))

            buffered: list[dict[str, Any]] = []

            def on_event(stage: str, payload: Any) -> None:
                if stage == "design":
                    buffered.append(self._row("design",
                                              "Architect designing detection"))
                elif stage == "redteam":
                    buffered.append(self._row("redteam",
                                              "Red-team generating attack"))
                elif stage == "translate":
                    buffered.append(self._row("translate",
                                              f"Translator writing SPL (iter {payload})",
                                              iteration=payload))
                elif stage == "validate":
                    buffered.append(self._row("validate",
                                              f"Validator backtesting (iter {payload})",
                                              iteration=payload))
                elif stage == "result":
                    r: ValidationResult = payload
                    buffered.append(self._row(
                        "result",
                        f"iter {r.iteration}: tp={r.tp_caught} fp={r.fp_count}",
                        iteration=r.iteration,
                        tp_caught=int(r.tp_caught),
                        fp_count=r.fp_count,
                        spl=r.spl,
                        sample_fps=r.sample_fps,
                    ))
                elif stage == "tune":
                    buffered.append(self._row("tune",
                                              "Architect tuning detection"))
                elif stage == "deploy":
                    buffered.append(self._row("deploy",
                                              "Deploying saved search"))
                elif stage == "deployed":
                    buffered.append(self._row("deployed",
                                              f"Deployed: {payload}",
                                              saved_search=payload))
                elif stage == "incomplete":
                    buffered.append(self._row("incomplete",
                                              "Did not converge",
                                              fp_curve=payload))
                elif stage == "declined":
                    buffered.append(self._row("declined",
                                              "User declined deploy"))

            orch = Orchestrator()
            state = orch.run(
                threat_text,
                auto_approve=bool(self.auto_approve),
                on_event=on_event,
            )

            for row in buffered:
                yield row

            yield self._row(
                "summary",
                "Run complete",
                detection=state.design.title if state.design else None,
                mitre=",".join(state.design.mitre_techniques) if state.design else None,
                fp_curve=state.fp_curve,
                deployed=state.deployed_name,
                triage_steps=state.doc.triage_steps if state.doc else None,
            )
        except Exception as exc:  # noqa: BLE001 — surface as a row, never crash splunkd.
            yield self._row(
                "error",
                f"{type(exc).__name__}: {exc}",
                traceback=traceback.format_exc(),
            )


if __name__ == "__main__":
    dispatch(CounterspellCommand, sys.argv, sys.stdin, sys.stdout, __name__)

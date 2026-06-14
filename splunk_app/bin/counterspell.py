#!/usr/bin/env python3
"""Splunk custom search command that drives the Counterspell orchestrator.

Usage from the Splunk search bar / dashboard:

    | counterspell threat="threats/t1048_exfil.md"
    | counterspell threat_text="An attacker is exfiltrating data..."
    | counterspell threat="threats/t1110_bruteforce.md" auto_approve=true

Design note — why this shells out:
    Splunk's bundled Python does NOT have Counterspell's dependencies
    (pydantic, openai, ...) installed, and installing them into Splunk's Python
    risks clobbering Splunk's own bundled packages. So instead of importing the
    package here, this thin wrapper (which uses only the stdlib + splunklib)
    invokes the SYSTEM Python — where the deps already live — running
    scripts/cs_dashboard_runner.py, and streams its JSON events back as result
    rows. Nothing of Splunk's Python is touched.

    Locations come from cs_runtime.json shipped next to this file:
        {"python_exe": "...python.exe", "repo_path": "...counterspell"}
    (falling back to COUNTERSPELL_HOME / PATH discovery if absent).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

APP_BIN = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_BIN))

# splunklib ships with every Splunk install.
from splunklib.searchcommands import (  # noqa: E402
    Configuration,
    GeneratingCommand,
    Option,
    dispatch,
    validators,
)


def _runtime() -> tuple[str, Path]:
    """Resolve (python_exe, repo_path) for the orchestrator subprocess."""
    cfg_path = APP_BIN / "cs_runtime.json"
    python_exe = ""
    repo_path = ""
    if cfg_path.is_file():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            python_exe = cfg.get("python_exe", "") or ""
            repo_path = cfg.get("repo_path", "") or ""
        except Exception:  # noqa: BLE001 — fall through to discovery.
            pass
    if not repo_path:
        repo_path = os.environ.get("COUNTERSPELL_HOME", "")
    if not python_exe:
        # Last resort: whatever 'python' resolves to on splunkd's PATH.
        python_exe = "python"
    return python_exe, Path(repo_path) if repo_path else APP_BIN.parents[2]


@Configuration(type="reporting")
class CounterspellCommand(GeneratingCommand):
    """Runs the Counterspell loop in a subprocess and streams progress rows."""

    threat = Option(doc="Path to a threat markdown file.", require=False)
    threat_text = Option(doc="Inline threat description.", require=False)
    auto_approve = Option(
        doc="Deploy on convergence without the interactive gate. Default true "
            "in the dashboard (the interactive gate is a CLI-only feature).",
        require=False, default=True, validate=validators.Boolean(),
    )

    # Human-readable label per JSON stage, for the dashboard's progress panel.
    _STAGE_MSG = {
        "start": "Counterspell run beginning",
        "design": "Architect designing detection",
        "redteam": "Red-team generating + injecting attack",
        "translate": "Translator writing SPL",
        "validate": "Validator backtesting (via MCP)",
        "result": "Backtest result",
        "tune": "Architect tuning detection",
        "deploy": "Deploying saved search",
        "deployed": "Deployed",
        "incomplete": "Did not converge",
        "declined": "Deploy declined",
        "summary": "Run complete",
        "error": "Run error",
    }

    def _row(self, stage: str, **extra: Any) -> dict[str, Any]:
        row: dict[str, Any] = {
            "_time": time.time(),
            "stage": stage,
            "message": self._STAGE_MSG.get(stage, stage),
        }
        for k, v in extra.items():
            if v is None:
                continue
            row[k] = json.dumps(v, default=str) if isinstance(v, (dict, list)) else v
        return row

    def generate(self):  # noqa: D401 — SearchCommand contract.
        python_exe, repo = _runtime()
        runner = repo / "scripts" / "cs_dashboard_runner.py"

        if not runner.is_file():
            yield self._row("error",
                            message=f"runner not found at {runner} — check "
                                    f"cs_runtime.json repo_path")
            return

        cmd = [str(python_exe), str(runner)]
        if self.threat_text:
            cmd += ["--threat-text", str(self.threat_text)]
        elif self.threat:
            cmd += ["--threat", str(self.threat)]
        else:
            yield self._row("error", message="Provide threat= or threat_text=")
            return
        # The dashboard cannot service an interactive [y/N] gate, so we always
        # auto-approve here; the gate remains available in the CLI.
        cmd.append("--yes")

        # Force a clean import path: the deps live in the staged runtime's
        # vendored lib/ (added by the runner), not the user-profile site-packages
        # splunkd cannot read. Disable user-site and force UTF-8 so the JSON
        # stream is well-formed on Windows.
        env = dict(os.environ)
        env["PYTHONNOUSERSITE"] = "1"
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        # splunkd exports SSL_CERT_FILE / REQUESTS_CA_BUNDLE pointing at Splunk's
        # own CA bundle, which the service account often can't read — httpx then
        # crashes building its SSL context before any request. Drop them so httpx
        # falls back to the bundled certifi in lib/.
        for _ssl_var in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
                         "OPENSSL_CONF"):
            env.pop(_ssl_var, None)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=str(repo),
                env=env,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except Exception as exc:  # noqa: BLE001
            yield self._row("error",
                            message=f"failed to launch {python_exe}: {exc}")
            return

        # Drain stderr on a background thread so a chatty subprocess can never
        # deadlock on a full stderr pipe while we read stdout.
        import threading
        stderr_buf: list[str] = []

        def _drain_stderr() -> None:
            if proc.stderr is not None:
                for ln in proc.stderr:
                    stderr_buf.append(ln)

        t = threading.Thread(target=_drain_stderr, daemon=True)
        t.start()

        saw_event = False
        saw_terminal = False  # summary/deployed/incomplete/error from the runner
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue  # ignore any non-JSON noise on stdout
            stage = evt.get("stage", "event")
            saw_event = True
            if stage in ("summary", "deployed", "incomplete", "declined", "error"):
                saw_terminal = True
            yield self._row(
                stage,
                iteration=evt.get("iteration"),
                tp_caught=evt.get("tp_caught"),
                fp_count=evt.get("fp_count"),
                spl=evt.get("spl"),
                sample_fps=evt.get("sample_fps"),
                saved_search=evt.get("saved_search"),
                detection=evt.get("detection"),
                mitre=evt.get("mitre"),
                fp_curve=evt.get("fp_curve"),
                deployed=evt.get("deployed"),
                triage_steps=evt.get("triage_steps"),
                chars=evt.get("chars"),
                error=evt.get("message") if stage == "error" else None,
                traceback=evt.get("traceback"),
            )

        proc.wait()
        t.join(timeout=5)
        stderr_tail = "".join(stderr_buf)[-1500:]
        # If the run produced no clean terminal event, surface the subprocess
        # stderr so failures are diagnosable instead of silent.
        if not saw_event or not saw_terminal or proc.returncode not in (0, None):
            yield self._row(
                "error",
                error=f"orchestrator exit {proc.returncode}; "
                      f"saw_event={saw_event} terminal={saw_terminal}",
                traceback=stderr_tail,
            )


if __name__ == "__main__":
    dispatch(CounterspellCommand, sys.argv, sys.stdin, sys.stdout, __name__)

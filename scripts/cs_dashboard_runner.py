"""JSON event runner for the in-Splunk dashboard's `| counterspell` command.

The custom search command (which runs inside splunkd's bundled Python, where
Counterspell's dependencies are NOT installed) shells out to the system Python
and invokes THIS script. We run the real orchestrator here — same loop the CLI
uses — and emit one compact JSON object per progress event to stdout, flushed
immediately so the dashboard streams the run live.

Output contract (one JSON object per line on stdout):
  {"stage": "start", "chars": N}
  {"stage": "design"|"redteam"|"tune"|"deploy"}
  {"stage": "translate"|"validate", "iteration": I}
  {"stage": "result", "iteration": I, "tp_caught": 0|1, "fp_count": N,
            "spl": "...", "sample_fps": [...]}
  {"stage": "deployed", "saved_search": "..."}
  {"stage": "incomplete", "fp_curve": [...]}
  {"stage": "summary", "detection": "...", "mitre": "...", "fp_curve": [...],
            "deployed": "...", "triage_steps": [...]}
  {"stage": "error", "message": "...", "traceback": "..."}

Anything the orchestrator prints elsewhere goes to stderr, keeping stdout a
clean JSON stream the command can parse.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import traceback
from pathlib import Path

# Keep stdout a pure JSON stream — route all logging to stderr so a stray
# log line never corrupts a result the command is parsing.
logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

REPO_ROOT = Path(__file__).resolve().parents[1]
# When this runtime is staged in a service-readable location (e.g.
# C:\Users\Public\counterspell) for the in-Splunk command, dependencies are
# vendored into a sibling lib/ so splunkd's subprocess can import them without
# touching the user-profile site-packages it cannot read. Harmless if absent.
_VENDORED_LIB = REPO_ROOT / "lib"
if _VENDORED_LIB.is_dir():
    sys.path.insert(0, str(_VENDORED_LIB))
sys.path.insert(0, str(REPO_ROOT / "src"))


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, default=str) + "\n")
    sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--threat-text", default="")
    parser.add_argument("--threat", default="")
    parser.add_argument("--yes", action="store_true",
                        help="Auto-approve deploy on convergence.")
    args = parser.parse_args()

    try:
        # Load .env from the repo so the orchestrator gets Splunk/LLM/MCP creds
        # regardless of the (minimal) environment splunkd hands the subprocess.
        try:
            from dotenv import load_dotenv
            load_dotenv(REPO_ROOT / ".env")
        except Exception:  # noqa: BLE001 — dotenv is best-effort here.
            pass

        from counterspell import Orchestrator  # noqa: E402
        from counterspell.schemas import ValidationResult  # noqa: E402

        if args.threat_text:
            threat_text = args.threat_text
        elif args.threat:
            p = Path(args.threat)
            if not p.is_absolute():
                p = REPO_ROOT / p
            threat_text = p.read_text(encoding="utf-8")
        else:
            _emit({"stage": "error", "message": "Provide --threat-text or --threat"})
            return 2

        _emit({"stage": "start", "chars": len(threat_text)})

        def on_event(stage: str, payload) -> None:
            if stage in ("design", "redteam", "tune", "deploy"):
                _emit({"stage": stage})
            elif stage in ("translate", "validate"):
                _emit({"stage": stage, "iteration": payload})
            elif stage == "result":
                r: ValidationResult = payload
                _emit({
                    "stage": "result",
                    "iteration": r.iteration,
                    "tp_caught": int(r.tp_caught),
                    "fp_count": r.fp_count,
                    "spl": r.spl,
                    "sample_fps": r.sample_fps,
                })
            elif stage == "deployed":
                _emit({"stage": "deployed", "saved_search": payload})
            elif stage == "incomplete":
                _emit({"stage": "incomplete", "fp_curve": payload})
            elif stage == "declined":
                _emit({"stage": "declined"})

        orch = Orchestrator()
        state = orch.run(threat_text, auto_approve=args.yes, on_event=on_event)

        _emit({
            "stage": "summary",
            "detection": state.design.title if state.design else None,
            "mitre": ",".join(state.design.mitre_techniques) if state.design else None,
            "fp_curve": state.fp_curve,
            "deployed": state.deployed_name,
            "triage_steps": state.doc.triage_steps if state.doc else None,
        })
        return 0
    except Exception as exc:  # noqa: BLE001 — surface as a JSON event, never crash silently.
        _emit({
            "stage": "error",
            "message": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        })
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

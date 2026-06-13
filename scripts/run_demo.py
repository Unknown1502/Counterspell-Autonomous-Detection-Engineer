"""CLI demo: run the Counterspell loop against a threat markdown file with rich output."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

# Windows consoles default to cp1252, which cannot encode the emoji/box-drawing
# glyphs the demo prints. Force UTF-8 so the recorded run never crashes on output.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from counterspell import Orchestrator  # noqa: E402
from counterspell.schemas import RunState, ValidationResult  # noqa: E402

console = Console()


def on_event(stage: str, payload: Any) -> None:
    """Render orchestrator progress events as styled console output."""
    if stage == "design":
        console.print("[bold cyan]🧠 Architect designing detection...[/]")
    elif stage == "redteam":
        console.print("[bold yellow]🔴 Red-team generating synthetic attack...[/]")
    elif stage == "translate":
        console.print(f"[bold blue]✍️  Translator writing SPL (iteration {payload})...[/]")
    elif stage == "validate":
        console.print(f"[bold blue]🔍 Validator running backtest (iteration {payload})...[/]")
    elif stage == "result":
        result: ValidationResult = payload
        fp_color = "red" if result.fp_count > 0 else "green"
        body = Text()
        body.append(f"iteration: {result.iteration}\n")
        body.append(f"tp_caught: {result.tp_caught}\n")
        body.append("fp_count: ", style="bold")
        body.append(f"{result.fp_count}\n", style=fp_color)
        body.append("\nSPL:\n", style="bold")
        body.append(result.spl)
        console.print(Panel(body, title=f"Backtest Result — iter {result.iteration}",
                            border_style=fp_color))
    elif stage == "tune":
        console.print("[bold yellow]🔧 Architect tuning detection (too many FPs)...[/]")
    elif stage == "deploy":
        console.print("[bold green]🚀 Deploying detection to Splunk...[/]")
    elif stage == "deployed":
        console.print(f"[bold green]✅ Deployed: {payload}[/]")
    elif stage == "incomplete":
        console.print(f"[bold red]⚠️  Loop did not converge. FP curve: {payload}[/]")
    elif stage == "declined":
        console.print("[bold red]❌ Deploy declined by user.[/]")


def _summary(state: RunState) -> None:
    title = state.design.title if state.design else "(no design)"
    mitre = ", ".join(state.design.mitre_techniques) if state.design else ""
    deployed = state.deployed_name or "(not deployed)"
    triage = state.doc.triage_steps if state.doc else []
    body = Text()
    body.append(f"Detection: {title}\n", style="bold")
    body.append(f"MITRE techniques: {mitre}\n")
    body.append(f"FP curve: {state.fp_curve}\n")
    body.append(f"Deployed name: {deployed}\n")
    body.append("Triage steps:\n", style="bold")
    for step in triage:
        body.append(f"  • {step}\n")
    console.print(Panel(body, title="Counterspell — Run Summary", border_style="cyan"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--threat", required=True, help="Path to threat markdown file")
    parser.add_argument("--yes", action="store_true", help="Auto-approve deploy")
    args = parser.parse_args()
    threat_text = open(args.threat).read()
    orch = Orchestrator()
    state = orch.run(threat_text, auto_approve=args.yes, on_event=on_event)
    _summary(state)

"""Run Counterspell on every threat in threats/ and produce a coverage report.

This is the script you use to:
  - regenerate run logs for the Navigator layer in one shot
  - sanity-check that the loop generalizes across all demo threats
  - produce the headline number for the Devpost write-up
    ("3 detections shipped, N total false positives, X minutes")

Usage:
    python scripts/run_all_demos.py
    python scripts/run_all_demos.py --yes              # auto-approve all deploys
    python scripts/run_all_demos.py --threats t1048_exfil.md t1110_bruteforce.md
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from counterspell import Orchestrator  # noqa: E402
from counterspell.schemas import RunState  # noqa: E402

console = Console()


def _stage_event(stage: str, payload) -> None:
    if stage == "design":
        console.print("  [cyan]→ design[/]")
    elif stage == "redteam":
        console.print("  [yellow]→ red-team[/]")
    elif stage == "translate":
        console.print(f"  [blue]→ translate (iter {payload})[/]")
    elif stage == "validate":
        console.print(f"  [blue]→ validate (iter {payload})[/]")
    elif stage == "result":
        color = "green" if payload.fp_count == 0 else "yellow" if payload.fp_count < 10 else "red"
        console.print(f"  [{color}]= iter {payload.iteration}: "
                      f"tp={payload.tp_caught}, fp={payload.fp_count}[/]")
    elif stage == "tune":
        console.print("  [yellow]→ tune[/]")
    elif stage == "deployed":
        console.print(f"  [bold green]✅ deployed: {payload}[/]")
    elif stage == "incomplete":
        console.print(f"  [red]⚠️  did not converge: {payload}[/]")
    elif stage == "declined":
        console.print("  [red]✗ deploy declined[/]")


def _summarize(results: list[tuple[Path, RunState, float]]) -> None:
    table = Table(title="Counterspell — Multi-Threat Run Summary",
                  show_lines=True, header_style="bold")
    table.add_column("Threat", style="cyan", no_wrap=True)
    table.add_column("Detection")
    table.add_column("MITRE", justify="left")
    table.add_column("FP curve", justify="right")
    table.add_column("Final FP", justify="right")
    table.add_column("Deployed?", justify="center")
    table.add_column("Elapsed", justify="right")

    total_iters = 0
    deployed_count = 0
    final_fps = []
    for path, state, elapsed in results:
        detection = state.design.title if state.design else "(none)"
        mitre = ", ".join(state.design.mitre_techniques) if state.design else ""
        curve = "→".join(str(c) for c in state.fp_curve) or "—"
        final = state.fp_curve[-1] if state.fp_curve else None
        deployed = "[green]yes[/]" if state.deployed_name else "[red]no[/]"
        if state.deployed_name:
            deployed_count += 1
        if final is not None:
            final_fps.append(final)
        total_iters += len(state.iterations)
        table.add_row(path.name, detection, mitre, curve,
                      "—" if final is None else str(final),
                      deployed, f"{elapsed:.1f}s")
    console.print(table)

    headline = Text()
    headline.append(f"{deployed_count} / {len(results)} detections shipped",
                    style="bold green" if deployed_count == len(results) else "bold yellow")
    if final_fps:
        headline.append(f" · total final FPs: {sum(final_fps)}")
    headline.append(f" · total iterations: {total_iters}")
    elapsed_total = sum(e for _, _, e in results)
    headline.append(f" · total elapsed: {elapsed_total / 60:.1f} min")
    console.print(Panel(headline, title="Headline", border_style="bold cyan"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threats", nargs="+", default=None,
                        help="Specific threat filenames (default: every *.md in threats/)")
    parser.add_argument("--yes", action="store_true",
                        help="Auto-approve every deploy")
    parser.add_argument("--stop-on-fail", action="store_true",
                        help="Halt the batch if a single run fails to converge")
    args = parser.parse_args(argv)

    threats_dir = REPO_ROOT / "threats"
    if args.threats:
        files = [threats_dir / n for n in args.threats]
    else:
        files = sorted(threats_dir.glob("*.md"))
    files = [f for f in files if f.exists()]
    if not files:
        console.print(f"[red]No threats found in {threats_dir}[/]")
        return 1

    console.print(Panel(f"Running Counterspell on {len(files)} threat(s)",
                        border_style="cyan"))

    orch = Orchestrator()
    results: list[tuple[Path, RunState, float]] = []
    for path in files:
        console.rule(f"[bold cyan]{path.name}[/]")
        start = time.time()
        state = orch.run(path.read_text(encoding="utf-8"),
                         auto_approve=args.yes, on_event=_stage_event)
        elapsed = time.time() - start
        results.append((path, state, elapsed))
        if args.stop_on_fail and not state.deployed_name:
            console.print("[red]Stopping batch (--stop-on-fail set)[/]")
            break

    _summarize(results)
    console.print("\n[dim]Next: python scripts/export_navigator_layer.py "
                  "→ load coverage.json in the ATT&CK Navigator.[/]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

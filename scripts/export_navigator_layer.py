"""Export a MITRE ATT&CK Navigator layer from Counterspell run logs.

Reads every JSONL file under runs/ and produces coverage.json — drop it into
https://mitre-attack.github.io/attack-navigator/ to render a coverage map.

Why this matters
----------------
The Navigator layer is the security industry's universal artifact for
detection coverage. Producing one automatically from real run logs is
proof — not narrative — that Counterspell measurably extends coverage.

Usage
-----
    python scripts/export_navigator_layer.py
    python scripts/export_navigator_layer.py --runs runs/ --out coverage.json
    python scripts/export_navigator_layer.py --deployed-only
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

# Navigator layer schema reference: https://github.com/mitre-attack/attack-navigator
LAYER_VERSION = "4.5"
ATTACK_VERSION = "14"   # Splunk's Foundation-Sec / ES integrations target this branch


def _iter_records(runs_dir: Path):
    if not runs_dir.is_dir():
        return
    for jsonl in sorted(runs_dir.glob("*.jsonl")):
        with jsonl.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def _collect_coverage(records, deployed_only: bool) -> dict[str, dict[str, Any]]:
    """Return {technique_id: {count, detections, min_fp, max_fp, last_iter_count}}."""
    coverage: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "count": 0,
        "detections": [],
        "min_fp": None,
        "max_fp": None,
        "iterations_total": 0,
    })
    for rec in records:
        outcome = rec.get("outcome", "")
        if deployed_only and outcome != "deployed":
            continue
        state = rec.get("state") or {}
        design = state.get("design") or {}
        techniques = design.get("mitre_techniques") or []
        deployed = state.get("deployed_name")
        iters = state.get("iterations") or []
        last_fp = iters[-1].get("fp_count") if iters else None

        for tid in techniques:
            tid = (tid or "").strip().upper()
            if not tid.startswith("T"):
                continue
            slot = coverage[tid]
            slot["count"] += 1
            slot["detections"].append({
                "title": design.get("title"),
                "deployed_name": deployed,
                "outcome": outcome,
                "fp_curve": [it.get("fp_count") for it in iters],
            })
            slot["iterations_total"] += len(iters)
            if last_fp is not None:
                slot["min_fp"] = last_fp if slot["min_fp"] is None else min(slot["min_fp"], last_fp)
                slot["max_fp"] = last_fp if slot["max_fp"] is None else max(slot["max_fp"], last_fp)
    return coverage


def _score(slot: dict[str, Any]) -> int:
    """0–100. 100 = a deployed detection with 0 final FPs."""
    if slot["count"] == 0:
        return 0
    base = 50
    if any(d["outcome"] == "deployed" for d in slot["detections"]):
        base = 80
    if slot["min_fp"] is not None and slot["min_fp"] == 0:
        base += 20
    return min(base, 100)


def _build_layer(coverage: dict[str, dict[str, Any]]) -> dict[str, Any]:
    techniques = []
    for tid, slot in sorted(coverage.items()):
        comments = []
        for d in slot["detections"][:5]:
            curve = d.get("fp_curve") or []
            tag = d.get("deployed_name") or d.get("title") or "(untitled)"
            curve_str = "→".join(str(c) for c in curve) if curve else "no iters"
            comments.append(f"{tag} [{d['outcome']}] FP: {curve_str}")
        techniques.append({
            "techniqueID": tid,
            "score": _score(slot),
            "color": "",
            "comment": "\n".join(comments),
            "enabled": True,
            "metadata": [
                {"name": "Counterspell runs", "value": str(slot["count"])},
                {"name": "Total iterations",
                 "value": str(slot["iterations_total"])},
                {"name": "Best (lowest) final FP",
                 "value": "n/a" if slot["min_fp"] is None else str(slot["min_fp"])},
            ],
            "showSubtechniques": False,
        })

    return {
        "name": "Counterspell coverage",
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": "4.9.1",
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": (
            "MITRE ATT&CK technique coverage produced by Counterspell — "
            "an autonomous detection engineer for Splunk. Score 80+ = a "
            "deployed saved search exists for this technique; +20 if the "
            "detection converged to zero false positives."
        ),
        "filters": {"platforms": ["Linux", "Windows", "macOS", "Network",
                                  "PRE", "Containers", "Office 365",
                                  "SaaS", "Google Workspace", "IaaS",
                                  "Azure AD"]},
        "sorting": 3,
        "layout": {"layout": "side",
                   "aggregateFunction": "average",
                   "showID": True,
                   "showName": True,
                   "showAggregateScores": True,
                   "countUnscored": False},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Designed (not deployed)", "color": "#ff6666"},
            {"label": "Deployed (some FPs)", "color": "#ffe766"},
            {"label": "Deployed (zero FPs)", "color": "#8ec843"},
        ],
        "metadata": [
            {"name": "Generated by", "value": "Counterspell"},
            {"name": "Total distinct techniques", "value": str(len(techniques))},
        ],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", default=str(REPO_ROOT / "runs"),
                        help="Directory containing *.jsonl run logs")
    parser.add_argument("--out", default=str(REPO_ROOT / "coverage.json"),
                        help="Path to write the Navigator layer JSON")
    parser.add_argument("--deployed-only", action="store_true",
                        help="Only count runs that resulted in a deployed saved search")
    args = parser.parse_args(argv)

    runs_dir = Path(args.runs)
    records = list(_iter_records(runs_dir))
    if not records:
        print(f"No run logs found in {runs_dir}", file=sys.stderr)
        print("  Run the orchestrator at least once first.", file=sys.stderr)
        return 1

    coverage = _collect_coverage(records, deployed_only=args.deployed_only)
    layer = _build_layer(coverage)
    out_path = Path(args.out)
    out_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")

    deployed = sum(1 for r in records if r.get("outcome") == "deployed")
    print(f"Read {len(records)} run(s) — {deployed} deployed")
    print(f"Wrote {out_path}  ({len(coverage)} distinct MITRE techniques)")
    print("Load it: https://mitre-attack.github.io/attack-navigator/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

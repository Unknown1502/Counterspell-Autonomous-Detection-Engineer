"""Generalization proof: does the deployed rule fire on noise it was never tuned against?

This is the on-screen answer to the sharpest judge question — "would this work
on real data, or only on the noise you planted to make your own demo look
good?"

The data generator seeds a SECOND class of benign noise tagged
`cs_holdout=true` (large legit off-site backups, a batch service account with
clustered auth failures, encoded PowerShell from an unseen legit parent). The
tuning loop never sees these: the Validator excludes `cs_holdout=true` rows
from the FP count and from the Architect's sample FPs. So the rule the agent
produces was tuned ONLY against the primary noise.

This script takes a deployed detection's SPL and runs it restricted to the
holdout set. If it fires on zero holdout events, the rule generalizes — it
learned the benign *pattern*, not the specific events it was shown.

Usage:
    # Check the most recently deployed rule from today's run log:
    python scripts/check_generalization.py

    # Or check a specific saved search by name:
    python scripts/check_generalization.py --name "Counterspell - <title>"

    # Or check a raw SPL string:
    python scripts/check_generalization.py --spl 'search index=counterspell ...'
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from counterspell.config import Config  # noqa: E402
from counterspell.mcp_client import MCPClient  # noqa: E402
from counterspell.splunk_client import SplunkClient  # noqa: E402

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _latest_deployed_spl() -> tuple[str | None, str | None]:
    """Return (saved_search_name, spl) of the most recent 'deployed' run today."""
    runs_dir = REPO_ROOT / "runs"
    if not runs_dir.exists():
        return None, None
    files = sorted(runs_dir.glob("*.jsonl"))
    for path in reversed(files):
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        for line in reversed(lines):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("outcome") != "deployed":
                continue
            state = rec.get("state") or {}
            iters = state.get("iterations") or []
            if not iters:
                continue
            name = state.get("deployed_name")
            spl = iters[-1].get("spl")
            if spl:
                return name, spl
    return None, None


def _holdout_count(rows: list[dict]) -> int:
    """Count result rows that carry the holdout marker, if it survived aggregation."""
    n = 0
    for r in rows:
        for key in ("cs_holdout", "holdout"):
            if str(r.get(key, "")).strip().lower() in ("true", "1", "yes"):
                n += 1
                break
    return n


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", help="Deployed saved search name to look up")
    parser.add_argument("--spl", help="Raw SPL to test directly")
    args = parser.parse_args()

    cfg = Config.load()
    splunk = SplunkClient(
        host=cfg.splunk_host, port=cfg.splunk_port, token=cfg.splunk_token,
        hec_url=cfg.hec_url, hec_token=cfg.hec_token, index=cfg.index,
    )
    mcp = MCPClient(mcp_url=cfg.mcp_url, mcp_token=cfg.mcp_token, fallback=splunk)

    name = args.name
    spl = args.spl
    if not spl:
        if args.name:
            try:
                ss = splunk.service.saved_searches[args.name]
                spl = ss.content.get("search", "")
            except Exception as e:  # noqa: BLE001
                print(f"{RED}Could not read saved search {args.name!r}: {e}{RESET}")
                return 1
        else:
            name, spl = _latest_deployed_spl()
            if not spl:
                print(f"{RED}No deployed run found in runs/. Run a demo first, "
                      f"or pass --name / --spl.{RESET}")
                return 1

    print(f"{BOLD}Generalization check{RESET}")
    print(f"  rule: {name or '(from --spl)'}")
    print(f"  SPL : {spl[:120]}{'...' if len(spl) > 120 else ''}\n")

    # Restrict the rule's evaluation to the holdout set only. We wrap the
    # rule's own search by appending a holdout filter where the rule already
    # references the index; if it's a raw `search` we add the constraint.
    holdout_spl = spl.strip()
    if "cs_holdout" not in holdout_spl:
        # Inject the holdout constraint right after the index reference.
        holdout_spl = holdout_spl.replace(
            'index="counterspell"', 'index="counterspell" cs_holdout="true"', 1
        )
        if "cs_holdout" not in holdout_spl:
            holdout_spl = holdout_spl.replace(
                "index=counterspell", "index=counterspell cs_holdout=true", 1
            )

    print(f"{YELLOW}Running deployed rule against the holdout set "
          f"(noise it was never tuned on)...{RESET}")
    t0 = time.time()
    try:
        rows = mcp.run_query(holdout_spl, earliest="-31d", latest="now")
    except Exception as e:  # noqa: BLE001
        print(f"{RED}Holdout search failed: {e}{RESET}")
        return 1
    elapsed = time.time() - t0

    fired = _holdout_count(rows) if _holdout_count(rows) else len(rows)
    print(f"  rule produced {len(rows)} row(s) over the holdout set "
          f"in {elapsed:.1f}s\n")

    if fired == 0:
        print(f"{GREEN}{BOLD}✓ GENERALIZES.{RESET} The deployed rule fired on "
              f"{GREEN}0{RESET} holdout events — benign patterns it was never "
              f"tuned against. It learned the pattern, not the planted noise.")
        return 0

    print(f"{RED}{BOLD}✗ DID NOT GENERALIZE.{RESET} The rule fired on {RED}{fired}{RESET} "
          f"holdout event(s). It may be overfit to the primary noise. "
          f"Re-run tuning or widen the design's exclusions.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

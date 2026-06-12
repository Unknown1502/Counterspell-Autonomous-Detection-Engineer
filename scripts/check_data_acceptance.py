"""Automate the data-model acceptance checks from docs/06_DATA_MODEL.md.

Run after seeding to confirm the synthetic baseline has:
  • all three sourcetypes with sensible volumes
  • benign auth-failure noise spread across many users (not all on one)
  • a small but non-zero count of large legitimate transfers
  • no duplicated cs_scenario_id stamps from prior runs leaking in

Exit code is 0 iff every check passes — wire it into CI later if desired.

    python scripts/check_data_acceptance.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from counterspell.config import Config  # noqa: E402
from counterspell.splunk_client import SplunkClient  # noqa: E402


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
DIM = "\033[2m"
RESET = "\033[0m"


def ok(msg: str) -> None:
    print(f"{GREEN}  ✓{RESET} {msg}")


def fail(msg: str, hint: str = "") -> None:
    print(f"{RED}  ✗{RESET} {msg}")
    if hint:
        print(f"{DIM}     → {hint}{RESET}")


def warn(msg: str) -> None:
    print(f"{YELLOW}  !{RESET} {msg}")


def _make_client(cfg: Config) -> SplunkClient:
    return SplunkClient(
        host=cfg.splunk_host,
        port=cfg.splunk_port,
        token=cfg.splunk_token,
        hec_url=cfg.hec_url,
        hec_token=cfg.hec_token,
        index=cfg.index,
    )


def check_sourcetype_volumes(c: SplunkClient, idx: str) -> bool:
    print("\n[1. sourcetype volumes]")
    spl = (f'search index="{idx}" earliest=-30d latest=now '
           f'| stats count by sourcetype')
    rows = c.oneshot(spl)
    counts = {r.get("sourcetype"): int(r.get("count", 0)) for r in rows}
    wanted = {"cs:auth", "cs:process", "cs:network"}
    found = set(counts.keys())
    missing = wanted - found
    passed = True
    if missing:
        fail(f"missing sourcetypes: {sorted(missing)}",
             "Re-run data/generate_synthetic_data.py")
        passed = False
    for st in sorted(wanted & found):
        n = counts[st]
        if n < 3000:
            fail(f"{st}: only {n:,} events in 30d — expected ≥ ~6,000",
                 "Re-run data/generate_synthetic_data.py")
            passed = False
        else:
            ok(f"{st}: {n:,} events")
    return passed


def check_auth_failure_spread(c: SplunkClient, idx: str) -> bool:
    print("\n[2. auth failure noise spread across users]")
    spl = (f'search index="{idx}" sourcetype=cs:auth action=failure '
           f'earliest=-30d latest=now '
           f'| stats count by user | sort -count')
    rows = c.oneshot(spl)
    if not rows:
        fail("no failed-auth events found",
             "The generator should produce ~3% auth failures")
        return False
    distinct = len(rows)
    top = int(rows[0].get("count", 0))
    total = sum(int(r.get("count", 0)) for r in rows)
    if distinct < 10:
        fail(f"only {distinct} distinct users have failures — expected ≥ 10",
             "Confirm the generator's user pool size")
        return False
    if total and top / total > 0.5:
        fail(f"single user accounts for {top}/{total} = "
             f"{top / total:.0%} of failures — too concentrated",
             "Tune _auth_event() to spread failures more evenly")
        return False
    ok(f"{distinct} distinct users with failures; "
       f"top user {top}/{total} = {top / total:.0%}")
    return True


def check_large_legit_transfers(c: SplunkClient, idx: str) -> bool:
    print("\n[3. small but non-zero large-transfer noise]")
    spl = (f'search index="{idx}" sourcetype=cs:network '
           f'bytes_out>50000000 earliest=-30d latest=now '
           f'| stats count')
    rows = c.oneshot(spl)
    n = int(rows[0].get("count", 0)) if rows else 0
    if n == 0:
        fail("no large outbound transfers in baseline — FP curve will start at 0",
             "Tune _network_event() to emit ~2% large transfers")
        return False
    if n > 500:
        warn(f"{n:,} large transfers — possibly noisy enough to dominate "
             "the FP curve; consider lowering the rate")
    ok(f"{n} large legitimate transfers in baseline noise")
    return True


def check_no_stale_scenario_stamps(c: SplunkClient, idx: str) -> bool:
    print("\n[4. no leaked cs_scenario_id from prior runs]")
    spl = (f'search index="{idx}" cs_scenario_id=* earliest=-7d latest=now '
           f'| stats dc(cs_scenario_id) as distinct')
    rows = c.oneshot(spl)
    distinct = int(rows[0].get("distinct", 0)) if rows else 0
    if distinct > 20:
        warn(f"{distinct} distinct red-team scenarios in last 7d — "
             "consider clearing the index between demo recordings")
        return True
    ok(f"{distinct} red-team scenario(s) present in last 7d "
       "(injection is expected; this is informational)")
    return True


def check_naive_detection_has_room_to_tune(c: SplunkClient, idx: str) -> bool:
    print("\n[5. naive detection finds enough FP candidates to tune]")
    spl = (f'search index="{idx}" sourcetype=cs:auth action=failure '
           f'earliest=-30d latest=now '
           f'| stats count')
    rows = c.oneshot(spl)
    n = int(rows[0].get("count", 0)) if rows else 0
    if n < 50:
        fail(f"only {n} failed-auth events total — FP curve has no room to drop",
             "Increase the 3% baseline failure rate in _auth_event()")
        return False
    ok(f"naive 'any failed login' detection finds {n} rows to triage "
       "(plenty of room for the tuning loop)")
    return True


def check_encoded_powershell_baseline(c: SplunkClient, idx: str) -> bool:
    """Noise floor for T1059.001 (encoded PowerShell)."""
    print("\n[6. benign encoded-PowerShell baseline (for T1059.001)]")
    spl = (f'search index="{idx}" sourcetype=cs:process process_name=powershell.exe '
           f'earliest=-30d latest=now '
           f'| search cmdline=*EncodedCommand* '
           f'| stats count by parent_process')
    rows = c.oneshot(spl)
    if not rows:
        fail("no benign encoded-PowerShell events in baseline",
             "Re-run the generator; check _process_event()'s 5% PowerShell path")
        return False
    parents = {r.get("parent_process") for r in rows}
    total = sum(int(r.get("count", 0)) for r in rows)
    ok(f"{total} benign encoded-PS events across {len(parents)} parent processes")
    return True


def check_beacon_baseline(c: SplunkClient, idx: str) -> bool:
    """Noise floor for T1071.001 (C2 beaconing)."""
    print("\n[7. periodic benign 'beacon' baseline (for T1071.001)]")
    spl = (f'search index="{idx}" sourcetype=cs:network bytes_out<5000 '
           f'earliest=-30d latest=now '
           f'| stats count by src_ip dest_ip '
           f'| where count>=10 '
           f'| sort -count | head 10')
    rows = c.oneshot(spl)
    if len(rows) < 3:
        fail(f"only {len(rows)} periodic small-payload src→dest pairs found",
             "Check _seed_beacon_baselines(); confirm BENIGN_BEACON_PROFILES seeds")
        return False
    ok(f"{len(rows)} (src→dest) pairs look like benign beacons "
       "(the T1071.001 detection must learn to exclude these)")
    return True


def check_build_host_baseline(c: SplunkClient, idx: str) -> bool:
    """Noise floor for CVE-2024-23897 (Jenkins CLI)."""
    print("\n[8. Jenkins/build-host activity baseline (for CVE-2024-23897)]")
    spl = (f'search index="{idx}" sourcetype=cs:process '
           f'host=jenkins-* OR host=build-* '
           f'earliest=-30d latest=now '
           f'| stats count by host process_name')
    rows = c.oneshot(spl)
    if not rows:
        fail("no events found on build hosts",
             "Confirm BUILD_HOSTS in the generator is populating; "
             "re-run the seeder")
        return False
    hosts = {r.get("host") for r in rows}
    total = sum(int(r.get("count", 0)) for r in rows)
    ok(f"{total} process events on {len(hosts)} build host(s)")
    return True


def check_backup_burst_baseline(c: SplunkClient, idx: str) -> bool:
    """Noise floor for T1486 (ransomware burst pattern)."""
    print("\n[9. daily backup-tool burst baseline (for T1486)]")
    spl = (f'search index="{idx}" sourcetype=cs:process user=svc_backup '
           f'earliest=-30d latest=now '
           f'| bucket _time span=1d '
           f'| stats count by _time '
           f'| where count>15')
    rows = c.oneshot(spl)
    if len(rows) < 15:
        fail(f"only {len(rows)} days with backup bursts — "
             f"expected ≥ 20 over 30 days (90% of days)",
             "Check _seed_backup_burst(); confirm BACKUP_HOST is being populated")
        return False
    ok(f"{len(rows)} days with legitimate backup bursts "
       "(the T1486 detection must learn to exclude svc_backup + backup tools)")
    return True


def check_roaming_user_baseline(c: SplunkClient, idx: str) -> bool:
    """Noise floor for T1078 (impossible travel)."""
    print("\n[10. roaming-user baseline (for T1078 impossible travel)]")
    spl = (f'search index="{idx}" sourcetype=cs:auth action=success '
           f'earliest=-30d latest=now '
           f'| stats dc(src_ip) as ips by user '
           f'| where ips>=3 '
           f'| sort -ips | head 10')
    rows = c.oneshot(spl)
    if len(rows) < 2:
        fail(f"only {len(rows)} users have ≥3 distinct source IPs — "
             "impossible-travel detection will start at 0 FPs",
             "Check ROAMING_USERS in the generator")
        return False
    ok(f"{len(rows)} 'roaming' users authenticate from multiple IPs "
       "(the T1078 detection must learn to tolerate these legitimate cases)")
    return True


def main() -> int:
    print(f"Counterspell data acceptance checks\n{'=' * 50}")
    try:
        cfg = Config.load()
        client = _make_client(cfg)
    except Exception as e:  # noqa: BLE001
        print(f"{RED}Setup failed: {e}{RESET}")
        print("Run scripts/verify_environment.py first.")
        return 1

    checks = [
        check_sourcetype_volumes,
        check_auth_failure_spread,
        check_large_legit_transfers,
        check_no_stale_scenario_stamps,
        check_naive_detection_has_room_to_tune,
    ]
    results = [fn(client, cfg.index) for fn in checks]
    print(f"\n{'=' * 50}\nSummary")
    if all(results):
        print(f"{GREEN}All acceptance checks passed.{RESET}")
        return 0
    failed = sum(1 for r in results if not r)
    print(f"{RED}{failed} check(s) failed. Fix the data before recording the demo.{RESET}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

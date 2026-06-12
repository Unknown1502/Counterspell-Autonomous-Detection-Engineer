"""Seed ~30 days of benign auth/process/network events into index=counterspell via HEC.

The generator produces deliberately-shaped noise so every threat in
`threats/` has something *plausible-but-benign* to be wrongly flagged by
a naive first-pass detection. Without this, the FP curve has no room to
drop and the demo's magic moment fails.

Noise types baked in
--------------------

| Threat target                          | Benign baseline produced                                   |
| -------------------------------------- | ---------------------------------------------------------- |
| T1110 (brute force)                    | ~3% random auth failures spread across many users          |
| T1048 (exfil)                          | ~2% large (50–500 MB) outbound transfers to varied IPs     |
| T1059.001 (encoded PowerShell)         | ~5% of process events are PowerShell -EncodedCommand from  |
|                                        | known automation parents (services.exe, ccmexec.exe, etc.) |
| T1071.001 (C2 beaconing)               | Persistent CDN/telemetry "beacons" — periodic small        |
|                                        | outbound connections to a small set of external IPs        |
| T1003.001 (LSASS dump)                 | Occasional benign procdump / comsvcs.dll admin debug runs  |
| T1078 (impossible travel)              | A subset of "roaming" users authenticate from multiple IPs |
|                                        | (VPN, home, internal) — same user, different /16s          |
| CVE-2024-23897 (Jenkins CLI)           | Build-host activity: java + jenkins-cli invocations,       |
|                                        | svc_jenkins authentications                                |
| T1486 (ransomware burst)               | Daily 20–35-event process bursts from backup tools         |
|                                        | (Veeam, wbengine, ConnectWise) on a designated backup host |

Run once after standing up Splunk + creating the HEC token:

    python data/generate_synthetic_data.py
"""

from __future__ import annotations

import json
import os
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")

HEC_URL = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
INDEX = "counterspell"

# Fallback ingestion path (REST receivers/simple on the management port) for
# when HEC is unavailable. Same _raw, same search-time fields as HEC.
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "localhost")
SPLUNK_PORT = os.environ.get("SPLUNK_PORT", "8089")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "")

# Set a seed via env to make the baseline exactly reproducible between recordings.
_seed = os.environ.get("COUNTERSPELL_SEED")
if _seed:
    random.seed(int(_seed))


# ---------------------------------------------------------------------------
# Population
# ---------------------------------------------------------------------------

USERS = (
    [f"user{i}" for i in range(1, 41)]
    + ["svc_backup", "svc_deploy", "svc_jenkins", "svc_monitor",
       "svc_db", "admin", "sysadmin"]
)
# A small subset of users legitimately appear from multiple IPs
# (mobile + wifi + VPN). This is what an "impossible travel" detection
# must learn to tolerate without flagging.
ROAMING_USERS = ["user5", "user12", "user23", "admin", "sysadmin"]

HOSTS = [f"host-{i:02d}" for i in range(1, 21)]
BUILD_HOSTS = ["jenkins-01", "build-02"]   # CVE-2024-23897 noise lives here
BACKUP_HOST = "host-15"                    # T1486 burst noise lives here
ALL_HOSTS = HOSTS + BUILD_HOSTS

APPS = ["sso", "vpn", "rdp", "ssh", "okta", "github", "jira", "webapp"]

# Generic admin/dev processes that should look uninteresting at a glance.
PROCESSES = [
    "chrome.exe", "python", "node", "powershell.exe", "bash", "java",
    "svchost.exe", "outlook.exe", "Code.exe", "git",
]
PARENTS = ["explorer.exe", "systemd", "init", "services.exe", "bash",
           "cmd.exe", "Code.exe"]

# Legitimate parents for PowerShell-with-EncodedCommand. The Architect must
# learn to exclude these to drop FPs on the T1059.001 detection.
LEGIT_POWERSHELL_PARENTS = [
    "services.exe", "ccmexec.exe", "taskeng.exe", "chocolatey.exe",
    "winrm.exe", "MsiExec.exe",
]
# Legitimate backup/RMM tools that produce process bursts. The T1486
# detection must exclude these to drop FPs.
BACKUP_BURST_TOOLS = [
    ("wbengine.exe", "services.exe"),
    ("VeeamAgent.exe", "Veeam.Backup.Manager.exe"),
    ("ConnectWiseControl.exe", "services.exe"),
    ("AcronisAgent.exe", "services.exe"),
]
# Sample legitimate Jenkins CLI invocations on build hosts.
JENKINS_CLI_ARGS = [
    "list-jobs", "build core-pipeline", "who-am-i", "version",
    "console core-pipeline 42", "list-plugins", "safe-restart",
]

PORTS = [80, 443, 22, 3389, 8080, 53, 8443]
PROTOS = ["tcp", "udp"]

# Periodic "beacon-like" benign traffic — CDNs, telemetry endpoints, update
# servers. These look statistically identical to a C2 beacon (regular
# interval, small payload, single destination), so the T1071.001 detection
# must learn the destination/asset context to drop FPs.
# Tuple: (src_ip, dest_ip, dest_port, interval_seconds, jitter, bytes_out)
BENIGN_BEACON_PROFILES = [
    ("10.0.5.10",  "151.101.1.5",  443, 300, 30, 2000),   # Fastly status
    ("10.0.10.20", "104.18.20.30", 443, 600, 60, 1500),   # Cloudflare
    ("10.0.7.15",  "23.40.0.1",    443, 900, 90,  800),   # Akamai
    ("10.0.3.42",  "8.8.8.8",       53, 120, 20,  120),   # DNS keepalive
]

# --- HOLDOUT GENERALIZATION SET -------------------------------------------
# A SECOND, structurally-different class of benign noise that the tuning loop
# never sees in its sample FPs (every holdout event is tagged cs_holdout=true).
# The agent tunes against the primary noise above; this set proves the rule it
# produces *generalizes* to benign patterns it was never shown — the answer to
# "would this work on real data or only on the noise you planted?"
#
# These are intentionally distinct in shape from the primary noise:
#   • exfil: large transfers, but to a DIFFERENT IP block on DIFFERENT ports
#   • brute force: failures clustered on a service account doing a bulk job
#   • encoded PowerShell: a different legitimate parent the agent never saw
# After a run converges, scripts/check_generalization.py asserts the deployed
# rule fires on ZERO cs_holdout=true events. That is the on-screen proof.
HOLDOUT_TAG = {"cs_holdout": "true"}

# Large but legitimate backups to an off-site repo — bursts of big transfers
# the exfil detection (T1048) must NOT flag. Different dest block (TEST-NET-1
# vs the primary noise's varied blocks) and different port profile.
HOLDOUT_BIG_TRANSFER_HOST = "10.0.250.5"   # the off-site backup gateway
HOLDOUT_BIG_TRANSFER_DEST = "192.0.2.250"  # the off-site repo
HOLDOUT_BIG_TRANSFER_PORTS = [873, 22]     # rsync / scp, not the attack's port

# A service account running a nightly batch that legitimately racks up auth
# failures (expired token mid-job) — must NOT be flagged as brute force (T1110).
HOLDOUT_BATCH_USER = "svc_nightly_etl"

# A legitimate encoded-PowerShell parent the primary noise never used, so the
# T1059.001 rule must generalize beyond the parents it was tuned against.
HOLDOUT_PS_PARENT = "intune-management-extension.exe"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _internal_ip() -> str:
    return f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _home_ip() -> str:
    return f"192.168.{random.randint(0, 5)}.{random.randint(1, 254)}"


def _external_ip() -> str:
    # Use TEST-NET ranges so we never collide with real public IPs.
    block = random.choice([
        "203.0.113",   # TEST-NET-3
        "198.51.100",  # TEST-NET-2
        "192.0.2",     # TEST-NET-1
    ])
    return f"{block}.{random.randint(1, 254)}"


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat()


def _ts_for_day(day_start: datetime) -> datetime:
    return day_start + timedelta(seconds=random.randint(0, 86399))


def _b64_payload(min_len: int = 60, max_len: int = 160) -> str:
    n = random.randint(min_len, max_len)
    alphabet = string.ascii_letters + string.digits + "+/"
    # PowerShell -enc payloads are valid base64; we just need shape, not validity.
    return "".join(random.choices(alphabet, k=n)) + "="


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------

def _auth_event(ts: datetime) -> dict:
    user = random.choice(USERS)
    # Roaming users sometimes use a different src_ip (VPN / home wifi)
    if user in ROAMING_USERS and random.random() < 0.4:
        src_ip = random.choice([_external_ip(), _home_ip(), _internal_ip()])
    else:
        src_ip = _internal_ip()

    # Jenkins service account auths come from build hosts
    if user == "svc_jenkins":
        host = random.choice(BUILD_HOSTS)
    else:
        host = random.choice(ALL_HOSTS)

    return {
        "_time": _iso(ts),
        "user": user,
        "src_ip": src_ip,
        "host": host,
        "action": "failure" if random.random() < 0.03 else "success",
        "app": random.choice(APPS),
    }


def _process_event(ts: datetime) -> dict:
    """A single benign process event with the various noise classes mixed in.

    Distribution roughly:
      ~5%   legitimate encoded PowerShell from automation parents
      ~0.2% benign procdump / comsvcs.dll admin debug runs
      ~30% of events on build hosts are Jenkins CLI invocations
      remainder: generic admin/dev process activity
    """
    host = random.choice(ALL_HOSTS)

    # Jenkins activity on build hosts
    if host in BUILD_HOSTS and random.random() < 0.30:
        cli_arg = random.choice(JENKINS_CLI_ARGS)
        return {
            "_time": _iso(ts),
            "host": host,
            "user": "svc_jenkins",
            "process_name": "java",
            "parent_process": "systemd",
            "cmdline": (
                f"java -jar jenkins-cli.jar -s http://localhost:8080 {cli_arg}"
            ),
        }

    r = random.random()

    # Legitimate PowerShell -EncodedCommand from automation
    if r < 0.05:
        return {
            "_time": _iso(ts),
            "host": host,
            "user": random.choice(USERS),
            "process_name": "powershell.exe",
            "parent_process": random.choice(LEGIT_POWERSHELL_PARENTS),
            "cmdline": (
                f"powershell.exe -NoP -W Hidden -EncodedCommand {_b64_payload()}"
            ),
        }

    # Rare benign procdump (sysadmin debugging a hung service)
    if r < 0.052:
        target = random.choice(["spoolsv", "sqlservr", "iexplore", "outlook"])
        return {
            "_time": _iso(ts),
            "host": host,
            "user": "admin",
            "process_name": "procdump.exe",
            "parent_process": "cmd.exe",
            "cmdline": f"procdump.exe -ma {target}",
        }

    # Generic varied admin/dev process activity
    cmdlines = [
        "--run --quiet",
        "-c 'import requests; requests.get(\"https://api.example.com\")'",
        "build --release",
        "/I install.msi /qn",
        "test --watch",
        "pull origin main",
        "--config /etc/app.yaml --port 8080",
    ]
    return {
        "_time": _iso(ts),
        "host": host,
        "user": random.choice(USERS),
        "process_name": random.choice(PROCESSES),
        "parent_process": random.choice(PARENTS),
        "cmdline": random.choice(cmdlines),
    }


def _network_event(ts: datetime) -> dict:
    # 2% of network events are large legit transfers — noise for T1048
    if random.random() < 0.02:
        bytes_out = random.randint(50 * 1024 * 1024, 500 * 1024 * 1024)
    else:
        bytes_out = random.randint(100, 50000)
    return {
        "_time": _iso(ts),
        "src_ip": _internal_ip(),
        "dest_ip": _external_ip(),
        "dest_port": random.choice(PORTS),
        "bytes_out": bytes_out,
        "bytes_in": random.randint(100, 20000),
        "protocol": random.choice(PROTOS),
    }


# ---------------------------------------------------------------------------
# Structured noise injectors (one call per day)
# ---------------------------------------------------------------------------

def _seed_beacon_baselines(day_start: datetime) -> list[dict]:
    """Inject periodic, small-payload, single-destination traffic that looks
    statistically like a C2 beacon but is actually CDN/telemetry. This is
    the noise the T1071.001 detection must learn to exclude."""
    out: list[dict] = []
    end = day_start + timedelta(days=1)
    for src_ip, dest_ip, port, interval, jitter, base_bytes in BENIGN_BEACON_PROFILES:
        # Offset start so the four profiles aren't synchronized.
        t = day_start + timedelta(seconds=random.randint(0, interval))
        while t < end:
            evt = {
                "_time": _iso(t),
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": port,
                "bytes_out": max(64, base_bytes + random.randint(-200, 400)),
                "bytes_in": random.randint(500, 3000),
                "protocol": "tcp" if port != 53 else "udp",
            }
            out.append(_envelope("cs:network", evt))
            t += timedelta(seconds=interval + random.randint(-jitter, jitter))
    return out


def _seed_backup_burst(day_start: datetime) -> list[dict]:
    """A daily 20–35-event process burst on the backup host. The T1486
    detection must learn to exclude these to drop FPs."""
    if random.random() > 0.9:  # 10% of days the backup is skipped (maintenance)
        return []
    burst_start = day_start + timedelta(
        hours=random.choice([2, 3, 22, 23]),
        minutes=random.randint(0, 30),
    )
    tool, parent = random.choice(BACKUP_BURST_TOOLS)
    out: list[dict] = []
    for i in range(random.randint(18, 35)):
        evt = {
            "_time": _iso(burst_start + timedelta(seconds=i * random.randint(1, 3))),
            "host": BACKUP_HOST,
            "user": "svc_backup",
            "process_name": tool,
            "parent_process": parent,
            "cmdline": (
                f"backup --src C:\\Data\\set{i:02d} "
                f"--dest \\\\backup-srv\\repo --compress"
            ),
        }
        out.append(_envelope("cs:process", evt))
    return out


def _seed_holdout(day_start: datetime) -> list[dict]:
    """Inject the holdout generalization set for one day.

    Every event carries cs_holdout=true so the tuning loop never sees these in
    its sample FPs. After a run converges, the deployed rule must fire on ZERO
    of these — that is the proof the rule generalizes beyond the noise it was
    tuned against, not just memorizes it.
    """
    out: list[dict] = []

    # 1. Legitimate large off-site backups (vs. T1048 exfil). 3-6 per day.
    for _ in range(random.randint(3, 6)):
        ts = _ts_for_day(day_start)
        out.append(_envelope("cs:network", {
            "_time": _iso(ts),
            "src_ip": HOLDOUT_BIG_TRANSFER_HOST,
            "dest_ip": HOLDOUT_BIG_TRANSFER_DEST,
            "dest_port": random.choice(HOLDOUT_BIG_TRANSFER_PORTS),
            "bytes_out": random.randint(80 * 1024 * 1024, 800 * 1024 * 1024),
            "bytes_in": random.randint(1000, 50000),
            "protocol": "tcp",
            **HOLDOUT_TAG,
        }))

    # 2. Service-account batch with clustered auth failures (vs. T1110). One
    #    burst on ~60% of days.
    if random.random() < 0.6:
        burst_start = _ts_for_day(day_start)
        host = random.choice(HOSTS)
        for i in range(random.randint(8, 20)):
            ts = burst_start + timedelta(seconds=i * random.randint(1, 4))
            out.append(_envelope("cs:auth", {
                "_time": _iso(ts),
                "user": HOLDOUT_BATCH_USER,
                "src_ip": _internal_ip(),
                "host": host,
                "action": "failure",
                "app": "etl",
                **HOLDOUT_TAG,
            }))

    # 3. Encoded PowerShell from a legit parent the primary noise never used
    #    (vs. T1059.001). 1-3 per day.
    for _ in range(random.randint(1, 3)):
        ts = _ts_for_day(day_start)
        out.append(_envelope("cs:process", {
            "_time": _iso(ts),
            "host": random.choice(HOSTS),
            "user": random.choice(USERS),
            "process_name": "powershell.exe",
            "parent_process": HOLDOUT_PS_PARENT,
            "cmdline": f"powershell.exe -NoP -W Hidden -EncodedCommand {_b64_payload()}",
            **HOLDOUT_TAG,
        }))

    return out


# ---------------------------------------------------------------------------
# HEC plumbing
# ---------------------------------------------------------------------------

def _envelope(sourcetype: str, fields: dict) -> dict:
    env: dict = {"event": fields, "sourcetype": sourcetype, "index": INDEX}
    # HEC's /event endpoint ignores the body's `_time` — promote it to the
    # envelope `time` (epoch seconds) or all 30 days of backfill would index
    # at receive-time and the backtest window logic would see one giant burst.
    ts = fields.get("_time")
    if ts:
        env["time"] = datetime.fromisoformat(
            str(ts).replace("Z", "+00:00")
        ).timestamp()
    return env


_use_rest_fallback = False  # set True after the first HEC failure


def _post_batch_rest(batch: list[dict]) -> None:
    """Fallback: POST raw JSON event lines to receivers/simple per sourcetype.

    The line content is the same JSON HEC would have indexed as _raw;
    timestamps come from each line's leading `_time` (auto ISO8601 detection).
    """
    by_st: dict[str, list[str]] = {}
    for env in batch:
        st = env.get("sourcetype", "cs:auth")
        by_st.setdefault(st, []).append(json.dumps(env.get("event") or {}))
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/receivers/simple"
    headers = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
    for st, lines in by_st.items():
        resp = requests.post(
            url, params={"index": INDEX, "sourcetype": st},
            headers=headers, data="\n".join(lines) + "\n",
            verify=False, timeout=120,
        )
        if not (200 <= resp.status_code < 300):
            raise RuntimeError(
                f"REST seed fallback failed ({resp.status_code}): {resp.text[:300]}"
            )


def _post_batch(batch: list[dict]) -> None:
    global _use_rest_fallback
    if not batch:
        return
    if not _use_rest_fallback and HEC_TOKEN:
        headers = {
            "Authorization": f"Splunk {HEC_TOKEN}",
            "Content-Type": "application/json",
        }
        body = "\n".join(json.dumps(e) for e in batch)
        try:
            resp = requests.post(
                HEC_URL, headers=headers, data=body, verify=False, timeout=60
            )
            if 200 <= resp.status_code < 300:
                return
            print(f"  HEC failed ({resp.status_code}) — using REST receivers fallback")
        except requests.RequestException as e:
            print(f"  HEC unreachable ({e}) — using REST receivers fallback")
        _use_rest_fallback = True
    elif not _use_rest_fallback and not HEC_TOKEN:
        print("  SPLUNK_HEC_TOKEN not set — using REST receivers fallback")
        _use_rest_fallback = True
    _post_batch_rest(batch)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not HEC_TOKEN and not SPLUNK_TOKEN:
        raise SystemExit(
            "Neither SPLUNK_HEC_TOKEN nor SPLUNK_TOKEN is set in .env — "
            "need one ingestion path (HEC or REST receivers fallback)."
        )

    now = datetime.now(timezone.utc).replace(microsecond=0)
    counts = {"auth": 0, "process": 0, "network": 0,
              "beacon": 0, "backup_burst": 0, "holdout": 0}
    batch: list[dict] = []
    batch_num = 0

    def _flush_if_full() -> None:
        nonlocal batch, batch_num
        if len(batch) >= 2000:
            batch_num += 1
            print(f"Posting batch {batch_num} ({len(batch)} events)...")
            _post_batch(batch)
            batch = []

    for day_offset in range(30, 0, -1):
        day_start = now - timedelta(days=day_offset)
        day_start = day_start.replace(hour=0, minute=0, second=0)

        n_auth = random.randint(300, 600)
        n_proc = random.randint(200, 400)
        n_net = random.randint(200, 400)

        for _ in range(n_auth):
            batch.append(_envelope("cs:auth", _auth_event(_ts_for_day(day_start))))
            counts["auth"] += 1
            _flush_if_full()

        for _ in range(n_proc):
            batch.append(_envelope("cs:process", _process_event(_ts_for_day(day_start))))
            counts["process"] += 1
            _flush_if_full()

        for _ in range(n_net):
            batch.append(_envelope("cs:network", _network_event(_ts_for_day(day_start))))
            counts["network"] += 1
            _flush_if_full()

        # Structured noise — beacons (T1071.001) and backup bursts (T1486)
        beacons = _seed_beacon_baselines(day_start)
        counts["beacon"] += len(beacons)
        for evt in beacons:
            batch.append(evt)
            counts["network"] += 1
            _flush_if_full()

        burst = _seed_backup_burst(day_start)
        counts["backup_burst"] += len(burst)
        for evt in burst:
            batch.append(evt)
            counts["process"] += 1
            _flush_if_full()

        # Holdout generalization set — tagged cs_holdout=true, never shown to
        # the tuning loop. The deployed rule must fire on zero of these.
        holdout = _seed_holdout(day_start)
        counts["holdout"] += len(holdout)
        for evt in holdout:
            st = evt.get("sourcetype", "")
            key = ("auth" if st == "cs:auth"
                   else "process" if st == "cs:process" else "network")
            counts[key] += 1
            batch.append(evt)
            _flush_if_full()

    if batch:
        batch_num += 1
        print(f"Posting batch {batch_num} ({len(batch)} events)...")
        _post_batch(batch)

    print(
        "Done. Seeded:\n"
        f"  cs:auth      {counts['auth']:>7,} events\n"
        f"  cs:process   {counts['process']:>7,} events "
        f"({counts['backup_burst']:,} from daily backup bursts)\n"
        f"  cs:network   {counts['network']:>7,} events "
        f"({counts['beacon']:,} from periodic benign 'beacons')\n"
        f"  holdout      {counts['holdout']:>7,} events "
        f"(cs_holdout=true — generalization set, never tuned against)\n"
        f"\nNext: python scripts/check_data_acceptance.py"
    )


if __name__ == "__main__":
    main()

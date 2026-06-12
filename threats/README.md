# Counterspell threat fixtures

Each file is a short, realistic SOC-analyst-style threat briefing — exactly
the shape a detection engineer would paste into Counterspell. The format
is intentional: 1–2 paragraphs of narrative, a "Characteristics to detect"
bullet list, MITRE mappings, sourcetypes needed, references.

## Headline demo set (use these in the 3-minute video)

| File | MITRE | Why this one for the video |
|---|---|---|
| [`t1048_exfil.md`](t1048_exfil.md) | T1048 | **The headline.** Network-side detection on `bytes_out` + unusual port. Cleanest FP curve drop because the noise floor is well-controlled in [`generate_synthetic_data.py`](../data/generate_synthetic_data.py). |
| [`t1110_bruteforce.md`](t1110_bruteforce.md) | T1110 | Auth-side classic. 20+ failed logins → one success. Good "B-roll" proof that the loop generalizes. |
| [`cve_2024_3094_xz.md`](cve_2024_3094_xz.md) | T1190 + T1059 + T1078 | Cross-sourcetype (`cs:auth` + `cs:process`), recent recognizable CVE. Strongest if the audience knows xz/CVE-2024-3094. |

## Extended portfolio (drives the Navigator coverage map)

| File | MITRE | Detection angle |
|---|---|---|
| [`t1059_powershell_encoded.md`](t1059_powershell_encoded.md) | T1059.001 + T1027 + T1140 | Encoded PowerShell — Living-off-the-Land binary abuse |
| [`t1071_c2_beacon.md`](t1071_c2_beacon.md) | T1071.001 + T1573 + T1095 | Cobalt Strike-style periodic beaconing (interval regularity, not volume) |
| [`t1003_lsass_dump.md`](t1003_lsass_dump.md) | T1003.001 | LSASS credential dumping (Mimikatz / procdump / `comsvcs.dll, #24`) |
| [`t1078_impossible_travel.md`](t1078_impossible_travel.md) | T1078 + T1078.004 + T1539 | Same user, disparate IPs in a short window — AiTM phishing fingerprint |
| [`cve_2024_23897_jenkins.md`](cve_2024_23897_jenkins.md) | T1190 + T1552.001 | Jenkins CLI arbitrary file read (real recent CVE) |
| [`t1486_ransomware_burst.md`](t1486_ransomware_burst.md) | T1486 + T1490 + T1489 + T1041 | Ransomware detonation: process burst + shadow-copy deletion + double-extortion exfil |

## What this portfolio proves

Combined, these 9 threats exercise **all three sourcetypes** (`cs:auth`,
`cs:process`, `cs:network`) and **13+ distinct MITRE techniques** — strong
evidence to a judge that Counterspell generalizes beyond hand-tuned demos.

Run them all in one batch and produce the Navigator coverage layer:

```powershell
python scripts/run_all_demos.py --yes
python scripts/export_navigator_layer.py --deployed-only
# load coverage.json at https://mitre-attack.github.io/attack-navigator/
```

## Why exactly these and not others

Every threat in this directory is one Counterspell can actually validate:

1. **Detectable in the 3 sourcetypes the agent understands.** Threats
   requiring registry, WMI, EDR telemetry, DNS query logs, or cloud-trail
   events are excluded — the prompts would hallucinate fields and the
   Validator would have nothing to match against. This is a feature, not
   a limitation: a tight schema keeps the LLM grounded.
2. **Has a clear attacker entity** (`user`, `src_ip`, or `host`) the
   Red-team agent can stamp on injected events so the Validator's TP
   attribution is deterministic.
3. **Has a noise-floor analog in the synthetic baseline.** The data
   generator emits a small fraction of benign-but-superficially-similar
   activity for each threat class so the first-iteration FP count starts
   non-zero — without that, the curve has no room to drop and the demo
   dies.

## Adding your own

Copy [`t1048_exfil.md`](t1048_exfil.md) as a template. A good threat
description for Counterspell:

- Is **1–2 paragraphs** of narrative (not pseudocode)
- Names **at least one MITRE technique** with the full ID
- Calls out **which Counterspell sourcetype(s)** the detection should use
- Describes the **attacker pattern in plain English** — Counterspell's
  Architect agent will translate that to SPL, so write for a security
  analyst, not for a SIEM
- Optionally references **public threat-intel sources** (NVD, Mandiant,
  research.splunk.com)

If the threat needs a sourcetype Counterspell doesn't have yet, add the
sourcetype to [`docs/06_DATA_MODEL.md`](../docs/06_DATA_MODEL.md), update
[`data/generate_synthetic_data.py`](../data/generate_synthetic_data.py)
to emit that flavor of benign noise, then write the threat.

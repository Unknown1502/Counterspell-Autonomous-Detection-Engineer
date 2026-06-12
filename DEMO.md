# Counterspell — 3-minute demo script

The single highest-leverage activity in week 3 is not writing more code.
It is re-recording the video until the FP curve drops convincingly on
screen. Read this first. Then read [docs/09_DEMO_SCRIPT.md](docs/09_DEMO_SCRIPT.md)
for the full beat-by-beat narration.

## What the judge sees

| Time | Visual | Voiceover thrust |
|---|---|---|
| 0:00–0:20 | Title slide | "Every SOC has the same bottleneck — writing detections." |
| 0:20–0:50 | Paste threat into dashboard; Architect panel updates live | "The Architect agent — a provider-agnostic, OpenAI-compatible model — reasons through the threat and maps it to MITRE T1048." |
| 0:50–1:30 | Translator → SPL on screen; Red-team injects; Validator reports "47 FPs" | "Validator runs against 30 days of historical data. Caught the attack. 47 FPs." |
| **1:30–2:20** | **FP curve drops: 47 → 12 → 0. HOLD on the 0 for 5 sec.** | **"Watch the false-positive count drop. Forty-seven. Twelve. Zero. No human touched this loop."** |
| 2:20–2:50 | Approval prompt → click Approve. Saved search appears in Splunk's Settings | "Counterspell pauses for human approval. On approval, the Deployer writes a real saved search via the SDK." |
| 2:50–3:00 | Title slide with: **3 detections shipped · 0 false positives · 8 minutes** | "The work that used to take a week, in three minutes." |

## The one moment that matters

Beat 4 — the FP curve dropping. Everything else is set-up and payoff.

**Make sure:**
- The dashboard's `Latest false-positive count` single-value tile is **visible the entire time** (it animates).
- The column chart in the second row shows three bars: tall red, medium yellow, tiny green.
- You hold on the final "0" for **at least 5 seconds**. Resist the urge to cut.

**Re-record if:**
- The voiceover talks over the transitions
- The total runtime is over 3:00
- The deployed saved search doesn't visibly appear in Splunk's Settings → Searches

## Pre-flight (run before pressing record)

```powershell
# 1. Confirm everything is up
python scripts/verify_environment.py

# 2. Confirm the data has room to tune
python scripts/check_data_acceptance.py

# 3. Warm the LLM cache (do one throwaway run so the second is fast)
python scripts/run_demo.py --threat threats/t1048_exfil.md --yes

# 4. Clear the runbook KV between takes so the deduplication panel resets
# (Splunk UI → Settings → Lookups → counterspell_runbook → delete entries)

# 5. Reset the index between takes if you want a fresh red-team injection
# (Splunk UI → Settings → Indexes → counterspell → Clean / Edit)
```

## Post-take checklist

- [ ] Total runtime ≤ 3:00
- [ ] FP curve drop is unambiguous (47 → 12 → 0, or similar)
- [ ] TP-caught panel is GREEN at the end
- [ ] Approval prompt is shown AND clicked on screen
- [ ] The saved search appears in Splunk's UI by the end
- [ ] Runbook entry is visible in the dashboard's row 5

## Demo threats — pick one

| Threat | Why use it |
|---|---|
| [`threats/t1048_exfil.md`](threats/t1048_exfil.md) | **The headline.** Network-side detection on `bytes_out` + non-standard port. The FP curve drops the cleanest because the noise floor is well-controlled. |
| [`threats/t1110_bruteforce.md`](threats/t1110_bruteforce.md) | Auth-side detection. Good as a second example to prove generalization. |
| [`threats/cve_2024_3094_xz.md`](threats/cve_2024_3094_xz.md) | Cross-sourcetype (`cs:auth` + `cs:process`). Strongest if the audience knows xz/CVE-2024-3094. |

The headline take should be t1048_exfil. The B-roll for the "and it
generalizes" claim is one of the other two.

## After the take

```powershell
# Export the MITRE Navigator coverage layer that proves the run was real
python scripts/export_navigator_layer.py --deployed-only
# Then: load coverage.json at https://mitre-attack.github.io/attack-navigator/
# and screenshot the heatmap for the Devpost write-up.
```

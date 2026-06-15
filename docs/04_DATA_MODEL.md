# 06 — Data Model

The data model is deliberately small. One index, three sourcetypes. The entire system reasons over this schema only — that constraint is what keeps the agents grounded and the demo reproducible.

## The index

| Index | Purpose |
|---|---|
| `counterspell` | All data — benign baseline and injected attacks. One index keeps the loop simple and the RBAC story clean. |

## The three sourcetypes

### `cs:auth` — authentication events

| Field | Type | Values / notes |
|---|---|---|
| `_time` | timestamp | Event time |
| `user` | string | Username, e.g. `user12`, `svc_backup`, `admin` |
| `src_ip` | string | Source IP (mix of internal `10.0.x.x` and external) |
| `host` | string | Target host, e.g. `host-04` |
| `action` | string | `success` or `failure` |
| `app` | string | `okta`, `vpn`, `ssh`, `rdp`, `webapp` |

### `cs:process` — process execution events

| Field | Type | Values / notes |
|---|---|---|
| `_time` | timestamp | Event time |
| `host` | string | Host where the process ran |
| `user` | string | Owning user |
| `process_name` | string | E.g. `powershell.exe`, `python`, `bash` |
| `parent_process` | string | Parent process name |
| `cmdline` | string | Full command line |

### `cs:network` — network connection events

| Field | Type | Values / notes |
|---|---|---|
| `_time` | timestamp | Event time |
| `src_ip` | string | Internal source IP |
| `dest_ip` | string | Destination IP (mostly external) |
| `dest_port` | integer | `80`, `443`, `22`, `3389`, `8080`, `53` typical |
| `bytes_out` | integer | Outbound byte count |
| `bytes_in` | integer | Inbound byte count |
| `protocol` | string | `tcp` or `udp` |

## Special injection field: `cs_scenario_id`

Every event the Red-team injects via HEC is stamped at injection time with `cs_scenario_id = <scenario.scenario_id>`. The Validator uses this to deterministically attribute a result row to the attack — that is what makes TP/FP measurement reliable and what makes the FP curve trustworthy.

This field is **not** present on benign events. Its absence on a result row that matches the attacker by user/IP/host is also treated as a TP signal (covers aggregated rows that drop the field).

## Benign baseline (what the data generator seeds)

Approximately 30 days of events, several thousand per day, across the three sourcetypes. The generator seeds **deliberately-shaped noise for every threat in `threats/`** so each detection has a plausible-but-benign baseline to be wrongly flagged at first iteration.

### Random baseline volume

- **cs:auth** — 300–600 events per day. ~3% failures as benign noise (T1110).
- **cs:process** — 200–400 events per day. Mixed admin/dev process activity.
- **cs:network** — 200–400 events per day. ~2% large legitimate transfers, 50–500 MB outbound (T1048).

### Structured noise (one set per day)

Beyond the random baseline, the generator injects shaped patterns each day so every threat has FP room to tune:

| Pattern | Volume | Tunes which detection |
|---|---|---|
| Periodic CDN/telemetry "beacons" — 4 fixed `(src_ip → dest_ip)` pairs on regular intervals (300–900 s) with jitter | ~250–500 events/day | **T1071.001** (C2 beaconing). Looks statistically identical to a real beacon — detection must learn destination/asset context. |
| Backup-tool process burst on `BACKUP_HOST` — 18–35 child processes within ~60 s, from `wbengine.exe` / `VeeamAgent.exe` / `ConnectWiseControl.exe` / `AcronisAgent.exe` | One burst/day on ~90% of days | **T1486** (ransomware burst). Detection must exclude `svc_backup` + known backup-tool parents. |
| Encoded-PowerShell from automation parents (`services.exe`, `ccmexec.exe`, `taskeng.exe`, `chocolatey.exe`, `winrm.exe`, `MsiExec.exe`) | ~5% of cs:process events | **T1059.001**. Detection must exclude legitimate automation parents. |
| Benign procdump on hung admin services (target ∈ `spoolsv`, `sqlservr`, `iexplore`, `outlook`), parent = `cmd.exe`, user = `admin` | ~0.2% of cs:process events | **T1003.001**. Detection must exclude admin-debug procdump targets. |
| Jenkins/build-host activity on `jenkins-01`, `build-02` — `java -jar jenkins-cli.jar` invocations under `svc_jenkins` | ~30% of cs:process events on build hosts | **CVE-2024-23897**. Detection must distinguish legitimate CLI args from `@file` exploitation. |
| Roaming users (`user5`, `user12`, `user23`, `admin`, `sysadmin`) authenticate from a mix of internal / `192.168.x.x` / external IPs ~40% of the time | Embedded in cs:auth | **T1078** (impossible travel). Detection must tolerate VPN + wifi switches for known roaming users. |

### Why this matters

Without these structured baselines, a naive first-pass detection for any of the extended threats produces **zero false positives**, the FP curve has nowhere to drop from, and the demo's magic moment fails. **Invest more time in the data generator than you think you should.**

### Populations

| Constant | Members | Purpose |
|---|---|---|
| `USERS` | 40 generic + 7 service/admin | Auth + process draw from this pool |
| `ROAMING_USERS` | 5 of the above | T1078 (impossible travel) noise |
| `HOSTS` | `host-01` … `host-20` | Generic hosts |
| `BUILD_HOSTS` | `jenkins-01`, `build-02` | CVE-2024-23897 noise |
| `BACKUP_HOST` | `host-15` | T1486 noise |
| `BENIGN_BEACON_PROFILES` | 4 `(src_ip, dest_ip, port, interval)` tuples | T1071.001 noise |

### Reproducibility

Set `COUNTERSPELL_SEED` to make the entire baseline deterministic between recordings:

```powershell
$env:COUNTERSPELL_SEED=42; python data/generate_synthetic_data.py
```

Same seed → same events → same FP curve every take. Drop the seed for a fresh baseline.

## Attack injections (what the Red-team adds)

Per scenario, 5 to 30 events spread across a short recent window (typically 15 minutes to 4 hours). All attributable to a single attacker entity. Examples:

- **Brute force (T1110):** 20+ failed logins from one IP against one user within 5 minutes, followed by one success.
- **Exfiltration (T1048):** Several `cs:network` events from one internal IP to one external IP, totalling > 1 GB outbound on an unusual port within an hour.

The attacker entity in the scenario (`user`, `src_ip`, `host`) is what the Validator matches result rows against for TP attribution.

## TP / FP definition (deterministic, value-exact)

A `ValidationResult` is computed as follows:

1. Run the candidate SPL over the last ~31 days (bounded).
2. For each result row, classify it **value-exact** (not substring-on-a-blob):
   - **TP** if any field *value* equals the scenario's `cs_scenario_id`, or
     equals one of the attacker's `user` / `src_ip` / `host` values — matched
     as a whole token. Multi-value cells (e.g. `values(src_ip)` lists) are
     split on whitespace/`,`/`;`/`|` so the attacker IP matches as a token,
     but a `count` of `4799` never matches the IP `…99`.
   - **FP** otherwise.
3. **Holdout rows (`cs_holdout=true`) are excluded from the FP count** and never
   shown to the Architect — see "Holdout generalization set" below.
4. `tp_caught` = at least one TP row exists.
5. `fp_count` = number of non-holdout FP rows.
6. `sample_fps` = up to five FP rows passed back to the Architect for grounded tuning.

This is intentionally rule-based. No LLM judges TP/FP — the Validator is
deterministic so the FP curve is reproducible.

> **Why value-exact and not substring.** The earlier implementation stringified
> the whole row and checked whether a marker appeared *anywhere* in the blob.
> That let a benign `count=4799` get attributed to attacker IP `10.99.99.99`
> (because `"99"` appears in `"4799"`), inflating TPs and hiding real FPs.
> Value-exact token matching closes that hole — pinned by
> `tests/test_validator.py::test_count_ending_in_attacker_ip_digits_is_not_a_false_tp`.

## Holdout generalization set (`cs_holdout=true`)

The plain version of synthetic data — "plant noise, then remove it" — invites
the fair critique that the system only solves a problem it created. The holdout
set is the answer.

The generator seeds a **second, structurally-different class of benign noise**,
tagged `cs_holdout=true`, that the tuning loop **never sees**:

| Holdout pattern | Distinct from primary noise how | Tests which detection generalizes |
|---|---|---|
| Large legitimate off-site backups from `10.0.250.5` → `192.0.2.250` on ports `873`/`22` | Different src/dest/ports than the primary 2% large-transfer noise | **T1048** exfil |
| `svc_nightly_etl` batch job racking up clustered auth failures | A single service account, not the spread-across-users primary failures | **T1110** brute force |
| Encoded PowerShell from `intune-management-extension.exe` | A legit parent the primary noise never used | **T1059.001** |

The Validator excludes these from the FP count and from the Architect's sample
FPs, so the rule is tuned **only** against the primary noise. After convergence,
`scripts/check_generalization.py` runs the *deployed* rule restricted to the
holdout set and asserts it fires on **zero** of it.

A green `✓ GENERALIZES` is the on-camera proof that the agent learned the benign
*pattern*, not the specific events it was shown — i.e. the behavior you'd expect
on real data, demonstrated on labeled data. This is the single strongest answer
to "is this just theater?"

## Synthetic vs. real life — the honest boundary

Do not claim Counterspell behaves identically on production data. It does not,
and a judge who runs a SOC will know. State the boundary precisely — being exact
about the gap is what makes the rest of the pitch credible.

### What is genuinely the same as real life

The **workflow and architecture** mirror real detection engineering:

- A detection engineer really does: read a threat → design logic → write SPL →
  **backtest against historical data** → tune down false positives → deploy a
  scheduled search. Counterspell automates that exact loop.
- Backtesting a candidate rule against history before shipping it **is** standard
  practice.
- The deploy is real — an actual saved search in actual Splunk, surviving a UI
  refresh.

So the *shape* of what Counterspell does is what the job actually looks like.

### What is easier in the demo than in reality

| Dimension | In the demo | In production |
|---|---|---|
| **Ground truth** | Free — every attack event is stamped `cs_scenario_id`, so TP/FP is known with certainty | Unknown — nobody knows which alerts are true positives; you need labeled data or analyst confirmation. This is the *entire reason SOCs are hard.* |
| **Noise shape** | Structured and learnable (a few benign patterns) | Long-tailed chaos — thousands of legitimate edge cases, seasonal behavior, that one finance job that legitimately moves 4 GB quarterly |
| **Reaching 0 FPs** | Realistic in ≤4 iterations on simple data | Optimistic — real tuning takes weeks and rarely hits literal zero |
| **Data volume** | ~30 K events, sub-1 GB, searches finish in seconds | Billions/day; the same `stats`/`tstats` could time out or cost real money |
| **The attack** | Generated by the Red-team to perfectly match the technique — catchable by construction | Evasive, blended with noise, no tidy marker; a real APT is not guaranteed catchable |
| **SPL quality ceiling** | Mediocre SPL still works because the data is simple | The rule must be genuinely good; quality depends entirely on the model |

### The claim you *can* defend

Not: *"Counterspell ships production detections."*

But: **"Counterspell proves an autonomous agent loop can design, backtest, tune,
and deploy a real Splunk detection — and the rule it produces generalizes to
benign patterns it was never tuned on."**

That is true, evidenced (the holdout test), and still impressive. You are
demonstrating that the *agentic workflow* works end to end — not that detection
engineering is solved.

### Why synthetic at all (three real reasons, in honesty order)

1. **Real customer logs cannot go in a public repo.** Synthetic is the only
   legal option. Every detection-engineering demo uses synthetic or sanitized
   data; judges know this.
2. **Deterministic ground truth.** The Validator must know *with certainty*
   which rows are the attack to compute a real FP count. Real data has no
   labels; `cs_scenario_id` gives a provable split instead of an LLM guess.
3. **Reproducibility.** Same seed → same baseline → same curve → a recordable
   demo.

### The path from demo to production (say this when asked)

The bridge to real data is **replacing synthetic ground truth with
analyst-confirmed labels** — which is exactly the human-in-the-loop the approval
gate already models. The agent proposes; a human confirms TP/FP; the loop tunes
against confirmed labels instead of stamped ones. The architecture does not
change; only the source of truth does.

## Why this data design works for the demo

- **It is small enough to live in a free trial** — total volume well under 1 GB.
- **It is large enough that backtests measure something real** — 30 days of mixed-sourcetype data with realistic noise.
- **It is reproducible** — the same generator seed produces the same baseline, so the demo's FP curve is consistent.
- **The schema is small enough to fit in every prompt** — that is what keeps the agents from hallucinating fields.

## Acceptance checks for the data generator

Before considering the data layer done, verify:

- [ ] `| tstats count by sourcetype` shows all three sourcetypes with sensible volumes
- [ ] `search index=counterspell action=failure | stats count by user` shows benign failure noise spread across many users (not all on one)
- [ ] `search index=counterspell sourcetype=cs:network bytes_out>50000000 | stats count` returns a small but non-zero count (the legitimate large transfers)
- [ ] A simple naive detection (e.g. "any failed login") produces clearly more rows than a tuned one would
- [ ] Re-running the generator does not duplicate events (events have realistic timestamps and the index is cleared between runs during development)

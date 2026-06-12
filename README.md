# Counterspell

[![tests](https://github.com/your-org/counterspell/actions/workflows/tests.yml/badge.svg)](https://github.com/your-org/counterspell/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![Splunk](https://img.shields.io/badge/Splunk-Enterprise%2BMCP%2BAI%20Assistant-orange)](https://splunkbase.splunk.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](https://attack.mitre.org/)

**An autonomous detection engineer for Splunk.**

Paste in a threat — a Mandiant report, a CVE, a MITRE technique — and a team of
five AI agents designs a Splunk detection, generates a synthetic attack to prove
it fires, backtests it against ~30 days of historical data, tunes false positives
out by itself, asks for human approval, and deploys it as a real, scheduled
saved search with a SOC runbook.

> The work that used to take a detection engineer a week, in three minutes.

```
   threat in  →  design  →  red-team  →  translate  →  validate
                                ↑                          │
                                └──── tune (≤4 iters) ─────┘
                                            │
                                       human approves
                                            │
                                  deploy saved search + runbook
```

---

## The five agents

| Agent | Powered by | What it does |
|---|---|---|
| **Architect** | OpenAI-compatible LLM | Reads the threat, produces a tunable `DetectionDesign` (MITRE techniques, sourcetypes, fields, logic, thresholds). On feedback, refines it. |
| **Red-team** | OpenAI-compatible LLM + HEC | Generates a small `AttackScenario` matching the technique and injects it via Splunk HEC so the loop has a guaranteed true positive. |
| **Translator** | Splunk AI Assistant (MCP) → LLM fallback | Converts detection logic into a runnable SPL search. |
| **Validator** | Pure Python | Runs the SPL via MCP (SDK fallback), splits result rows into TPs (matched on `cs_scenario_id` / attacker identity) and FPs. Excludes the `cs_holdout=true` set so the tuning loop never sees the generalization holdout. **Deterministic, no LLM.** |
| **Deployer** | OpenAI-compatible LLM + Splunk SDK | Writes a SOC runbook (`DetectionDoc`) and creates the real saved search + KV store entry. **ES-ready:** attaches notable + risk-based-alerting + correlation-search metadata when Enterprise Security is installed; ships a plain scheduled saved search otherwise. |

The LLM seat is **provider-agnostic** — any OpenAI-compatible endpoint works
(Splunk-hosted Foundation-Sec, Groq, Ollama, vLLM). Swapping providers is a
`.env` change, not a code change.

The full contracts and prompts live in [docs/04_AGENT_DESIGN.md](docs/04_AGENT_DESIGN.md)
and [docs/05_PROMPT_LIBRARY.md](docs/05_PROMPT_LIBRARY.md).

---

## Day-0 gate — do this first

Before any code runs, four external dependencies must be reachable.

1. **Splunk Enterprise trial** installed locally (60-day, on-prem) with the
   `counterspell` index created.
2. **Splunk add-ons** from Splunkbase installed:
   - MCP Server (v1.1.0+, for OAuth)
   - AI Assistant for SPL
   - AI Toolkit
3. **HEC token** named `counterspell_hec` scoped to `index=counterspell`.
4. **Hosted model** reachable on an OpenAI-compatible endpoint.
   Path A (recommended): Splunk-hosted Foundation-Sec.
   Path B: self-hosted via Ollama / vLLM.

Verify everything with:

```powershell
python scripts/verify_environment.py
```

Full Day-0 checklist: [docs/02_DAY0_GATE.md](docs/02_DAY0_GATE.md).

---

## Quickstart

```powershell
# 1. Clone and install
git clone <repo>
cd counterspell
python -m pip install -r requirements.txt

# 2. Configure secrets
Copy-Item .env.example .env
# edit .env — SPLUNK_TOKEN, SPLUNK_HEC_TOKEN, MCP_TOKEN, LLM_BASE_URL, LLM_API_KEY

# 3. Verify the environment is wired up
python scripts/verify_environment.py

# 4. Seed ~30 days of synthetic benign data (one-time, ~3 min)
python data/generate_synthetic_data.py

# 5. Run a detection end-to-end on the headline demo threat
python scripts/run_demo.py --threat threats/t1048_exfil.md
```

Expected output (abridged):

```
🧠 Architect designing detection...
🔴 Red-team generating synthetic attack...
✍️  Translator writing SPL (iteration 1)...
🔍 Validator running backtest (iteration 1)...
┌─ Backtest Result — iter 1 ──────────────────────┐
│ iteration: 1                                    │
│ tp_caught: True                                 │
│ fp_count: 47                                    │
└─────────────────────────────────────────────────┘
🔧 Architect tuning detection (too many FPs)...
...
┌─ Backtest Result — iter 3 ──────────────────────┐
│ iteration: 3                                    │
│ tp_caught: True                                 │
│ fp_count: 0                                     │
└─────────────────────────────────────────────────┘
Deploy this saved search to Splunk? [y/N] y
🚀 Deploying detection to Splunk...
✅ Deployed: Counterspell - Bulk Outbound Transfer to Single External IP
```

The deployed search now appears under **Settings → Searches, reports, and alerts**
in your Splunk UI. It ships **ES-ready**: when Enterprise Security is installed,
hits raise a notable event in **Incident Review** and contribute to
**Risk-Based Alerting**; without ES it deploys as a plain scheduled saved search
(still real, just no ES enrichment). The runbook entry lands in the
`counterspell_runbook` KV collection either way.

### Prove it generalizes (the sharpest judge question)

The Validator tunes the rule against the primary noise floor but never sees a
second, held-out class of benign events tagged `cs_holdout=true` (off-site
backups, a batch service account, encoded PowerShell from an unseen parent).
After deploying, run the deployed SPL against *only* that holdout set:

```powershell
python scripts/check_generalization.py
```

Zero hits means the rule learned the benign *pattern*, not the specific events
it was shown — it would hold up on data it was never tuned against.

---

## In-Splunk UX (recommended for the demo)

Install the bundled app so analysts can run Counterspell from the Splunk search bar:

```powershell
python scripts/package_app.py    # produces counterspell-0.1.0.tgz
# then: Splunk UI → Apps → Manage Apps → Install app from file → select the .tgz
```

After install, from the Splunk search bar:

```
| counterspell threat="threats/t1048_exfil.md"
```

The bundled dashboard (**Apps → Counterspell → Counterspell Console**)
shows the live FP curve, the final SPL, and a runbook listing.

The custom command requires the host's `splunkd` Python to be able to import the
`counterspell` package. Set `COUNTERSPELL_HOME` to this repo's path in
`$SPLUNK_HOME/etc/splunk-launch.conf`, and `pip install -e .` from the repo root
into Splunk's Python (`$SPLUNK_HOME/bin/python3 -m pip install ...`).

---

## Repository layout

```
counterspell/
├── README.md                ← you are here
├── LICENSE                  ← Apache 2.0
├── architecture.md          ← Mermaid system diagram
├── requirements.txt         ← pinned Python deps
├── .env.example             ← copy to .env, fill in secrets
├── config.yaml              ← non-secret runtime config
│
├── docs/                    ← design + scope + demo docs
│   ├── 01_OVERVIEW.md           pitch + scope
│   ├── 02_DAY0_GATE.md          environment prereqs
│   ├── 03_ARCHITECTURE.md       system + data flow
│   ├── 04_AGENT_DESIGN.md       per-agent contracts + JSON schemas
│   ├── 05_PROMPT_LIBRARY.md     LLM prompts (source of truth)
│   ├── 06_DATA_MODEL.md         index, sourcetypes, TP/FP definition
│   ├── 07_FILE_STRUCTURE.md     this layout, annotated
│   ├── 08_BUILD_SCHEDULE.md     day-by-day plan to deadline
│   └── 09_DEMO_SCRIPT.md        3-minute video script + submission checklist
│
├── src/counterspell/        ← the agent runtime
│   ├── config.py, schemas.py, prompts.py
│   ├── llm_client.py        OpenAI-compatible w/ JSON validate+retry
│   ├── splunk_client.py     SDK wrapper: oneshot, HEC, saved search, KV
│   ├── mcp_client.py        MCP JSON-RPC w/ transparent SDK fallback
│   ├── orchestrator.py      the loop + approval gate + iteration cap
│   └── agents/
│       ├── architect.py     design() + tune()
│       ├── translator.py    MCP-first, LLM fallback
│       ├── redteam.py       generate + HEC inject
│       ├── validator.py     deterministic TP/FP split
│       └── deployer.py      doc + saved-search write + KV upsert
│
├── data/
│   └── generate_synthetic_data.py    30 days of structured benign noise tuned per threat
│
├── threats/                 ← 9 demo input fixtures (see threats/README.md)
│   ├── README.md                       headline-demo set vs extended portfolio
│   │   ─── headline demo set (used in the video) ───
│   ├── t1048_exfil.md                  T1048 — data exfiltration (network)
│   ├── t1110_bruteforce.md             T1110 — brute force (auth)
│   ├── cve_2024_3094_xz.md             T1190+T1059+T1078 — xz backdoor
│   │   ─── extended portfolio (drives the Navigator coverage map) ───
│   ├── t1059_powershell_encoded.md     T1059.001 — encoded PowerShell LOLBin
│   ├── t1071_c2_beacon.md              T1071.001 — C2 beaconing
│   ├── t1003_lsass_dump.md             T1003.001 — LSASS credential dump
│   ├── t1078_impossible_travel.md      T1078 — auth from disparate geographies
│   ├── cve_2024_23897_jenkins.md       CVE-2024-23897 — Jenkins CLI file read
│   └── t1486_ransomware_burst.md       T1486 — ransomware detonation
│
├── splunk_app/              ← in-Splunk surface (packages to .tgz)
│   ├── bin/counterspell.py             custom search command
│   ├── default/app.conf, commands.conf, collections.conf, transforms.conf
│   ├── default/restmap.conf            reserved for future REST endpoints (empty in v0.1)
│   ├── default/data/ui/views/          the dashboard (single base search, 7 panel rows)
│   ├── default/data/ui/nav/            nav menu
│   ├── appserver/static/counterspell.css  dashboard styling
│   ├── static/appIcon.png + appIcon_2x.png
│   ├── metadata/default.meta
│   └── README.txt                      in-package install notes
│
├── scripts/
│   ├── run_demo.py                     single-threat CLI demo
│   ├── run_all_demos.py                multi-threat batch with Rich coverage report
│   ├── verify_environment.py           Day-0 gate checks
│   ├── check_data_acceptance.py        10 noise-floor acceptance checks
│   ├── check_generalization.py         runs the deployed SPL against the cs_holdout set
│   ├── export_navigator_layer.py       MITRE ATT&CK Navigator coverage JSON
│   ├── generate_icons.py               AppInspect icons
│   └── package_app.py                  builds the AppInspect-ready .tgz
│
└── tests/                   ← 76 tests: Validator, LLM client, MCP, Translator,
                                  Orchestrator (+extras for persistence/dedup/ES),
                                  Red-team repair, Deployer ES, Navigator export, Schemas
```

Detailed file responsibilities: [docs/07_FILE_STRUCTURE.md](docs/07_FILE_STRUCTURE.md).

---

## Why synthetic data (the question every judge will ask)

Counterspell's headline visual — the FP count dropping `47 → 12 → 0` across
iterations — requires three things that real data cannot provide on a 18-day
hackathon timeline:

1. **Deterministic ground truth.** The Validator must know with certainty which
   result rows are the attack. Every red-team event is stamped with
   `cs_scenario_id` at HEC inject time, plus a known attacker entity
   (`user`, `src_ip`, `host`). TP/FP attribution is rule-based, not LLM-judged.
2. **A tuned noise floor.** The generator bakes in 3% benign auth failures and
   2% large legitimate transfers. *That noise is what a naive first-pass
   detection wrongly flags* — without it, the FP curve starts at zero and the
   demo has no story.
3. **Reproducibility.** Same seed, same baseline, same curve. The demo is
   recordable.
4. **A generalization holdout.** A second class of benign noise is tagged
   `cs_holdout=true` and hidden from the tuning loop. `check_generalization.py`
   replays the deployed rule against only that set — a built-in answer to *"does
   this work on data you didn't plant?"*

Privacy (no real customer logs in a public repo) and pragmatics (a fresh Splunk
trial is empty) are bonus reasons. Full detail in
[docs/06_DATA_MODEL.md](docs/06_DATA_MODEL.md).

---

## Security guardrails (RBAC story)

These are not afterthoughts. They are part of the pitch:

- **Dedicated MCP service account** scoped to `index=counterspell` only (when
  MCP Server is enabled). Even a successful prompt-injection has a one-index
  blast radius.
- **OAuth 2.1 on MCP** (Splunk MCP Server v1.1.0+, when enabled — without MCP,
  all reads go through the documented SDK fallback under the same scoped token).
- **Human-approval gate** before any saved search is written. Shown on screen
  in the demo, enforced in [orchestrator.py:_confirm](src/counterspell/orchestrator.py#L18).
- **Iteration cap** (default 4) prevents runaway tuning loops from consuming
  the model budget.
- **No outbound actions.** No firewall API, no SOAR webhook, no Slack post.
  The only thing the agent writes to is the same Splunk instance it reads from.

---

## Out of scope (deliberate, do not ask)

These were considered and rejected for v1 — they would dilute the headline
"single tight loop that ships":

- Live alert triage
- SOAR / response actions
- Multi-tenant
- Custom fine-tuned model
- Slack / Jira / Confluence integrations

See [docs/01_OVERVIEW.md](docs/01_OVERVIEW.md#scope-two-pillars-only) for the
full scope debate.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

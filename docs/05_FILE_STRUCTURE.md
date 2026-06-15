# 07 — File Structure

This is the repo layout as built. Each file is described by its
**responsibility**, not its implementation. The build order at the end records
the dependency sequence the project was assembled in.

## Tree

```
counterspell/
├── README.md
├── LICENSE
├── architecture_diagram.md
├── requirements.txt
├── pyproject.toml
├── .env.example
├── config.yaml
│
├── docs/
│   ├── 01_OVERVIEW.md
│   ├── 02_DAY0_GATE.md
│   ├── 03_ARCHITECTURE.md
│   ├── 04_AGENT_DESIGN.md
│   ├── 05_PROMPT_LIBRARY.md
│   ├── 06_DATA_MODEL.md
│   ├── 07_FILE_STRUCTURE.md
│   ├── 08_BUILD_SCHEDULE.md
│   └── 09_DEMO_SCRIPT.md
│
├── src/
│   └── counterspell/
│       ├── __init__.py
│       ├── config.py
│       ├── schemas.py
│       ├── prompts.py
│       ├── llm_client.py
│       ├── splunk_client.py
│       ├── mcp_client.py
│       ├── orchestrator.py
│       └── agents/
│           ├── __init__.py
│           ├── architect.py
│           ├── translator.py
│           ├── redteam.py
│           ├── validator.py
│           └── deployer.py
│
├── data/
│   └── generate_synthetic_data.py
│
├── threats/
│   ├── README.md
│   ├── t1048_exfil.md                 (headline demo set)
│   ├── t1110_bruteforce.md
│   ├── cve_2024_3094_xz.md
│   ├── t1059_powershell_encoded.md    (extended portfolio)
│   ├── t1071_c2_beacon.md
│   ├── t1003_lsass_dump.md
│   ├── t1078_impossible_travel.md
│   ├── cve_2024_23897_jenkins.md
│   └── t1486_ransomware_burst.md
│
├── splunk_app/
│   ├── README.txt
│   ├── bin/
│   │   └── counterspell.py
│   ├── appserver/
│   │   └── static/
│   │       └── counterspell.css
│   ├── static/
│   │   ├── appIcon.png
│   │   └── appIcon_2x.png
│   ├── metadata/
│   │   └── default.meta
│   └── default/
│       ├── app.conf
│       ├── commands.conf
│       ├── collections.conf
│       ├── transforms.conf
│       ├── restmap.conf
│       └── data/
│           └── ui/
│               ├── nav/
│               │   └── default.xml
│               └── views/
│                   └── counterspell_dashboard.xml
│
├── scripts/
│   ├── run_demo.py
│   ├── run_all_demos.py
│   ├── verify_environment.py
│   ├── check_data_acceptance.py
│   ├── check_generalization.py
│   ├── export_navigator_layer.py
│   ├── generate_icons.py
│   └── package_app.py
│
└── tests/
    ├── conftest.py
    ├── test_schemas.py
    ├── test_llm_client.py
    ├── test_mcp_client.py
    ├── test_translator.py
    ├── test_redteam_repair.py
    ├── test_validator.py
    ├── test_orchestrator.py
    ├── test_orchestrator_extras.py
    ├── test_deployer_es.py
    └── test_export_navigator_layer.py
```

## Top-level files

| File | Responsibility |
|---|---|
| `README.md` | Project intro, doc index, day-0 gate, quickstart. The first thing a judge or teammate reads. |
| `LICENSE` | Apache 2.0 (matches Splunk's typical choice). |
| `architecture_diagram.md` | The Mermaid system diagram. Devpost submissions are stronger with a diagram; export to PNG for the write-up if needed. |
| `requirements.txt` | Pinned Python dependencies. Notable ones: `splunk-sdk`, `openai`, `pydantic`, `requests`, `pyyaml`, `python-dotenv`, `rich`. |
| `pyproject.toml` | Package metadata so `pip install -e .` works — required for the Splunk custom command to import `counterspell` from `splunkd`'s Python. |
| `.env.example` | Template for the secrets file (`SPLUNK_TOKEN`, `SPLUNK_HEC_TOKEN`, `MCP_TOKEN`, `LLM_BASE_URL`, etc). Copied to `.env` by each developer. Never committed with real values. |
| `config.yaml` | Non-secret configuration: the index name, the FP threshold, the max iteration count, the LLM model name. |

## Docs

| File | Responsibility |
|---|---|
| `01_OVERVIEW.md` | What Counterspell is, the pitch, why it wins, scope boundaries. |
| `02_DAY0_GATE.md` | The external dependencies that must be reachable before any code runs. |
| `03_ARCHITECTURE.md` | System diagram, component descriptions, data flow, failure isolation, RBAC. |
| `04_AGENT_DESIGN.md` | Each agent's contract, the JSON schemas, the orchestration loop in English. |
| `05_PROMPT_LIBRARY.md` | The exact prompts for every agent, with tuning notes. |
| `06_DATA_MODEL.md` | Index, sourcetypes, fields, the TP/FP definition, the `cs_holdout` generalization set, acceptance checks. |
| `07_FILE_STRUCTURE.md` | This file. |
| `08_BUILD_SCHEDULE.md` | The day-by-day plan to the deadline. |
| `09_DEMO_SCRIPT.md` | The 3-minute video script and the submission checklist. |

## `src/counterspell/` — the agent runtime

| File | Responsibility |
|---|---|
| `__init__.py` | Package marker; exposes `Orchestrator` and `Config`. |
| `config.py` | Loads `config.yaml` and `.env` into a single typed config object. |
| `schemas.py` | The Pydantic models that define every agent contract: `DetectionDesign`, `SplOutput`, `AttackScenario`, `ValidationResult`, `DetectionDoc`, `RunState`. |
| `prompts.py` | The runtime mirror of `05_PROMPT_LIBRARY.md`. Source of truth for what gets sent to the LLM. Keep this and the doc in sync. |
| `llm_client.py` | OpenAI-compatible LLM client. Talks to either Splunk-hosted models or self-hosted (vLLM, Ollama). Owns the JSON-validation-and-retry loop. |
| `splunk_client.py` | Splunk Python SDK wrapper. Owns oneshot search, HEC inject, saved-search create (with Enterprise Security notable/risk/correlation-search metadata), and the runbook KV record. |
| `mcp_client.py` | Splunk MCP Server JSON-RPC client. Tools used: `run_splunk_query`, `saia_generate_spl`. Transparently falls back to the SDK when MCP is down so development is never blocked. |
| `orchestrator.py` | The non-LLM brain. Runs the loop, holds `RunState`, emits progress events, enforces the iteration cap and the human-approval gate. |

### `src/counterspell/agents/` — one file per agent

| File | Responsibility |
|---|---|
| `architect.py` | `design()` for initial design; `tune()` for iteration. Both return `DetectionDesign`. |
| `translator.py` | Asks MCP `saia_generate_spl`; falls back to LLM. Returns SPL string. |
| `redteam.py` | Generates `AttackScenario` via LLM (with a JSON-repair retry path); injects events through the Splunk client. |
| `validator.py` | Deterministic Python. Runs the candidate SPL, splits rows into TP and FP, excludes the `cs_holdout=true` set from both the FP count and the Architect's sample FPs, returns `ValidationResult`. |
| `deployer.py` | Generates `DetectionDoc` via LLM; performs the real saved-search write via the SDK with notable + risk-based-alerting + correlation-search metadata. Never runs without explicit approval. |

## `data/` — the data layer

| File | Responsibility |
|---|---|
| `generate_synthetic_data.py` | Seeds ~30 days of benign auth, process, and network events into `index=counterspell` via HEC. Includes deliberate primary noise (failed logins, large legitimate transfers) so the FP curve has room to drop, plus a second `cs_holdout=true` class hidden from tuning for the generalization proof. |

## `threats/` — demo input fixtures

Nine threat briefings: a three-file **headline demo set** used in the video and
a six-file **extended portfolio** that drives the Navigator coverage map.
Together they exercise all three sourcetypes (`cs:auth`, `cs:process`,
`cs:network`) and 13+ distinct MITRE techniques. See
[`threats/README.md`](../threats/README.md) for the full table and the criteria
for adding your own.

## `splunk_app/` — the in-Splunk surface

This is what makes Counterspell *feel* like a Splunk-native tool rather than a
Python script. The whole directory is validated by AppInspect and packaged as a
`.tgz` for the submission by `scripts/package_app.py`.

| File | Responsibility |
|---|---|
| `bin/counterspell.py` | A Splunk custom search command. Lets analysts run `\| counterspell threat="..."` from a Splunk search bar. Internally it calls the same orchestrator. |
| `appserver/static/counterspell.css` | Dashboard styling. |
| `static/appIcon.png`, `appIcon_2x.png` | App icons (AppInspect requires both). |
| `metadata/default.meta` | App-level permissions/sharing. |
| `README.txt` | In-package install notes shipped inside the `.tgz`. |
| `default/app.conf` | Splunk app metadata (name, version, description, author). |
| `default/commands.conf` | Registers the `counterspell` custom search command. |
| `default/collections.conf` | Declares the `counterspell_runbook` KV store collection. |
| `default/transforms.conf` | Maps the KV collection to a lookup. |
| `default/restmap.conf` | Reserved for future REST endpoints (status polling, run history). Empty in v0.1 — the custom command is the only entry point. |
| `default/data/ui/nav/default.xml` | App nav menu. |
| `default/data/ui/views/counterspell_dashboard.xml` | SimpleXML dashboard (single base search, seven panel rows): run KPIs, the live FP curve, live agent progress, naive-vs-tuned SPL, run summary, MITRE coverage + runbook KV entries, and recently deployed saved searches from Splunk REST. |

## `scripts/` — operational

| File | Responsibility |
|---|---|
| `run_demo.py` | The CLI entry point for a single threat. Runs the orchestrator with progress events printed to the terminal, shows the human-approval prompt, prints the final FP curve and deployed-search name. This is what the video records. |
| `run_all_demos.py` | Multi-threat batch runner with a Rich coverage report across the full portfolio. |
| `verify_environment.py` | Day-0 gate checks — confirms Splunk, HEC, MCP, and the model endpoint are all reachable. |
| `check_data_acceptance.py` | 10 noise-floor acceptance checks on the seeded synthetic data. |
| `check_generalization.py` | Runs a deployed detection's SPL restricted to the `cs_holdout=true` set; zero hits proves the rule generalizes. |
| `export_navigator_layer.py` | Emits a MITRE ATT&CK Navigator coverage JSON (`--deployed-only` for shipped rules). |
| `generate_icons.py` | Generates the AppInspect app icons. |
| `package_app.py` | Builds the AppInspect-ready `.tgz`. |

## `tests/` — 76 tests

Test coverage focuses on the deterministic, contract-bearing parts of the
system (everything that is *not* an LLM call).

| File | Covers |
|---|---|
| `conftest.py` | Shared fixtures. |
| `test_schemas.py` | The Pydantic agent contracts. |
| `test_llm_client.py` | The OpenAI-compatible client and its JSON validate-and-retry loop. |
| `test_mcp_client.py` | MCP JSON-RPC calls and the transparent SDK fallback. |
| `test_translator.py` | MCP-first / LLM-fallback SPL generation. |
| `test_redteam_repair.py` | The red-team agent's JSON-repair retry path. |
| `test_validator.py` | The deterministic TP/FP split, including `cs_holdout` exclusion. |
| `test_orchestrator.py` | The loop, the iteration cap, and the approval gate. |
| `test_orchestrator_extras.py` | Persistence, dedup, and ES-related orchestration extras. |
| `test_deployer_es.py` | The Enterprise Security notable/risk/correlation-search saved-search metadata. |
| `test_export_navigator_layer.py` | The Navigator coverage export. |

Run them all with `pytest`.

## What is NOT in the file tree

These are intentionally absent and should stay absent:

- No `agents/triage.py`. No live triage.
- No `agents/responder.py`. No SOAR/response actions.
- No `slack_integration/`. No outbound notifications.
- No web UI beyond the Splunk dashboard. A separate React app is scope creep.

## Build order (which file got written when)

This is the dependency order. Following it means never blocking on a half-built
module.

1. `config.yaml`, `.env.example`, `requirements.txt`, `pyproject.toml`
2. `src/counterspell/config.py`, `schemas.py`, `prompts.py`
3. `src/counterspell/llm_client.py` — verify it can talk to your chosen model endpoint
4. `src/counterspell/splunk_client.py` — verify `oneshot()` and `create_saved_search()` against your trial
5. `data/generate_synthetic_data.py` — seed the data
6. `src/counterspell/mcp_client.py` — get one MCP call working
7. `src/counterspell/agents/architect.py`, `translator.py` — first two agents
8. `src/counterspell/agents/redteam.py`, `validator.py` — the loop becomes real
9. `src/counterspell/orchestrator.py` — wire the loop, no deploy yet
10. `src/counterspell/agents/deployer.py` — add the real write (+ ES metadata)
11. `scripts/run_demo.py` — CLI driver
12. `splunk_app/*` — in-Splunk UX
13. `scripts/*` — batch runner, acceptance, generalization, Navigator export, packaging
14. `tests/*` — lock in the deterministic contracts

The build schedule in `08_BUILD_SCHEDULE.md` maps these to specific dates.

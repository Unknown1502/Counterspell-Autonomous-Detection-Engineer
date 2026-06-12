# 04 — Agent Design

Five agents plus a deterministic Orchestrator. Each agent has one job. The Orchestrator is plain code, not an LLM — it owns the loop, the state, and the human-approval gate.

## Why this split

A single mega-agent given the whole task would wander, drift off-schema, and be impossible to debug. Splitting along the natural pipeline boundaries (design → translate → attack → validate → tune → deploy) means each agent has a tiny, testable contract and the loop is reproducible.

## Agent roster

| Agent | Engine | Job | Output (strict JSON) |
|---|---|---|---|
| Architect | Foundation-Sec Instruct (LLM) | Design the detection, then tune it each iteration | `DetectionDesign` |
| Translator | MCP `saia_generate_spl` (primary) + LLM fallback | Convert design into runnable SPL | `SplOutput` (a single SPL string) |
| Red-team | Foundation-Sec Instruct (LLM) | Generate synthetic attack events that exhibit the technique | `AttackScenario` |
| Validator | Deterministic Python over MCP `run_splunk_query` | Run the SPL, split rows into TP and FP, report metrics | `ValidationResult` |
| Deployer | Foundation-Sec (docs) + Splunk SDK (write) | Generate runbook documentation, then write the real saved search | `DetectionDoc` + saved-search name |
| Orchestrator | Plain Python (no LLM) | Run the loop, hold state, gate deploy on human approval | `RunState` (full record) |

## JSON contracts

These are the strict shapes every agent's LLM call must return. The Orchestrator parses each response against its schema and retries once with a repair instruction on parse failure.

### DetectionDesign — produced by the Architect

| Field | Type | Description |
|---|---|---|
| `title` | string | Short detection name |
| `mitre_techniques` | list of strings | MITRE ATT&CK technique IDs (e.g. `["T1110"]`) |
| `rationale` | string | One or two sentences on what behavior this catches |
| `sourcetypes` | list of strings | Subset of available sourcetypes |
| `key_fields` | list of strings | Fields the detection keys on |
| `logic` | string | Plain-English detection logic |
| `thresholds` | object | Named numeric thresholds (initial, deliberately loose) |
| `false_positive_notes` | string | Benign patterns that might trip this |

### SplOutput — produced by the Translator

| Field | Type | Description |
|---|---|---|
| `spl` | string | The full SPL search, starting with `search index="counterspell"` |

### AttackScenario — produced by the Red-team

| Field | Type | Description |
|---|---|---|
| `scenario_id` | string | Kebab-case unique ID; stamped on every injected event |
| `attacker` | object | `user`, `src_ip`, `host` of the simulated attacker |
| `window` | object | `earliest` and `latest` ISO-8601 timestamps for the attack |
| `events` | list of objects | Each has `sourcetype` and `fields` matching the schema |

### ValidationResult — produced by the Validator

| Field | Type | Description |
|---|---|---|
| `iteration` | integer | Which iteration of the loop this is (1-indexed) |
| `spl` | string | The exact SPL that was run |
| `tp_caught` | boolean | True if the attack scenario was caught |
| `fp_count` | integer | Number of false-positive result rows |
| `sample_fps` | list of objects | Up to five sample false-positive rows for the Tuner to see |

### DetectionDoc — produced by the Deployer

| Field | Type | Description |
|---|---|---|
| `saved_search_name` | string | E.g. `Counterspell - Brute Force Login` |
| `description` | string | One or two sentences for the runbook |
| `mitre_techniques` | list of strings | Final MITRE mapping |
| `triage_steps` | list of strings | Analyst steps if this fires |
| `validation_summary` | string | "Caught the simulated attack with 0 FPs after 3 iterations" |

### RunState — held by the Orchestrator, surfaced to the dashboard

| Field | Type | Description |
|---|---|---|
| `threat_text` | string | The original input |
| `design` | `DetectionDesign` | Latest version |
| `scenario` | `AttackScenario` | The injected attack |
| `iterations` | list of `ValidationResult` | One per loop pass; this is the FP curve |
| `deployed_name` | string or null | Set after deploy |
| `doc` | `DetectionDoc` or null | Set after deploy |

## The orchestration loop in plain English

1. Accept a threat string from the user.
2. Call **Architect** to produce the initial `DetectionDesign`.
3. Call **Red-team** to produce an `AttackScenario` for that design.
4. Inject the attack events into Splunk via HEC, stamped with the `scenario_id`.
5. Enter the loop (capped at four iterations by default):
   - a. Call **Translator** to produce SPL from the current design.
   - b. Call **Validator** to backtest the SPL and return a `ValidationResult`.
   - c. Append the result to `RunState.iterations` (this is what feeds the FP curve).
   - d. If `tp_caught` is true and `fp_count` is at or below threshold, exit the loop.
   - e. Otherwise call **Architect** with the result to produce a tuned design; continue.
6. If the loop converged, pause and ask the human for approval to deploy.
7. On approval, call **Deployer** to produce the runbook and write the saved search and KV record.
8. Return the full `RunState`.

## Agent-by-agent detail

### Architect

Has two methods: `design(threat_text)` for the initial pass and `tune(design, spl, result)` for every subsequent iteration. The tuning method receives the sample false positives so the model can see *what* benign patterns it is wrongly flagging — this grounded feedback is what makes the FP curve actually drop.

Temperature 0.2 (we want deterministic, structured output, not creativity).

### Translator

Primary path: ask the MCP server's `saia_generate_spl` tool, then pipe the result through `saia_optimize_spl`. This earns honest "uses AI Assistant for SPL" credit in the write-up.

Fallback path: if MCP is unavailable or returns nothing usable, ask the LLM directly with a strict prompt. Either way, the runtime normalizes the SPL to begin with `search index="counterspell"`.

Temperature 0.1 — SPL must be deterministic.

### Red-team

Generates between 5 and 30 events spread across a short recent window, all attributable to a single attacker entity. The runtime stamps every injected event with `cs_scenario_id = <scenario.scenario_id>` at HEC time, which is what the Validator uses to deterministically separate true positives from false positives.

Temperature 0.5 — some variety in event content is good; the *structure* is locked by the schema.

### Validator

No LLM here. This is deterministic Python. It:
1. Runs the candidate SPL via the MCP client (which falls back to the SDK if MCP is down).
2. Iterates over result rows.
3. A row is a **true positive** if it contains the attack `scenario_id` *or* the attacker's user / src_ip / host string (the latter handles aggregations that drop the scenario_id field).
4. Every other row is a **false positive**.
5. Returns a `ValidationResult`.

### Deployer

Two-stage:
1. **Document.** One LLM call produces the `DetectionDoc` (runbook).
2. **Deploy.** Pure SDK code: `service.saved_searches.create(name, spl, ...)` creates a real, schedulable saved search. The runbook is written to a KV store collection (`counterspell_runbook`) that the dashboard reads.

Deploy never runs without `auto_approve=False` consent or explicit `--yes` on the CLI. This is the guardrail story made concrete.

### Orchestrator

Plain code, no LLM. Responsible for:
- Loading config (model endpoint, Splunk credentials, FP threshold, max iterations).
- Holding `RunState`.
- Emitting events (`design`, `redteam`, `translate`, `validate`, `result`, `tune`, `deploy`, `deployed`) that the CLI and dashboard subscribe to for live progress.
- Enforcing the iteration cap.
- Enforcing the human-approval gate.

## Why no live-triage agent, no SOAR agent, no Slack agent

Every additional agent multiplies the surface area without adding to the magic moment. The magic moment is **the FP curve dropping**. Everything else is in service of that. If a feature does not feed the FP curve or the headline real-write action, it does not ship in v1.

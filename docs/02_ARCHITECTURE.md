# 03 — Architecture

## System diagram

```
                  Threat input
              (CVE / report / MITRE TID)
                       |
                       v
        +--------------------------------+
        |   Counterspell agent runtime    |
        |   (Python service, your code)   |
        |                                  |
        |   Orchestrator                   |
        |     |                            |
        |     +--> Architect agent         |
        |     +--> Translator agent        |
        |     +--> Red-team agent          |
        |     +--> Validator (no LLM)      |
        |     +--> Deployer agent          |
        +--------------------------------+
              |               |
              v               v
   Splunk MCP Server     Splunk Python SDK
   (reads, SPL gen,      (HEC inject,
   backtests)            saved-search write,
                         KV store)
              |               |
              +-------+-------+
                      v
              Splunk Enterprise
              index=counterspell
                      |
                      v
              Counterspell dashboard
              (FP curve, coverage, runbook)
```

## Components

### Counterspell agent runtime
A small Python service that owns the orchestration logic. It is the only place that calls the LLM. It is configurable to talk to either Splunk-hosted models or a self-hosted endpoint (Path A or Path B from `02_DAY0_GATE.md`). It is invokable two ways:
- From the command line, for development and demo.
- From inside Splunk, via a custom SPL command (`| counterspell threat="..."`) packaged in the Splunk app.

### Splunk MCP Server
Used for everything that is fundamentally a read or a search-generation task: running the backtest, asking AI Assistant for SPL, listing knowledge objects to avoid duplicating an existing detection. The MCP server enforces RBAC, so the agent operates under a dedicated service account scoped to `index=counterspell` only — this is your security and guardrails story.

### Splunk Python SDK
Used for the writes the MCP server is not designed to do: injecting synthetic attack events via HEC, creating the saved search (the headline "real action"), and writing the runbook to KV store. Both clients hit the same Splunk instance.

### Splunk Enterprise (the target instance)
One index (`counterspell`), three sourcetypes, ~30 days of seeded benign data plus injected attack events. Detail in `06_DATA_MODEL.md`.

### The Splunk app (`counterspell_app`)
A small in-Splunk surface providing:
- A custom search command, so an analyst can write `| counterspell threat="CVE-2026-1234"` directly in a Splunk search bar.
- A dashboard showing the live FP curve, the iteration history, and the runbook KV store contents.

## End-to-end data flow

1. **Threat in.** A user pastes a threat description into the dashboard, the CLI, or the custom command.
2. **Architect.** The runtime sends the threat plus the data schema to Foundation-Sec via the LLM endpoint, getting back a structured `DetectionDesign` (MITRE techniques, sourcetypes, fields, logic, initial thresholds).
3. **Red-team.** A second LLM call produces a small `AttackScenario` — synthetic events that match the technique, tagged with a unique `cs_scenario_id` for later attribution.
4. **Inject.** The runtime POSTs the attack events to HEC. The events land in `index=counterspell`.
5. **Translate.** The runtime asks the MCP server's `saia_generate_spl` tool to convert the design's natural-language logic into runnable SPL. If unavailable, the runtime falls back to an LLM-drafted SPL.
6. **Validate.** The runtime asks the MCP server's `run_splunk_query` tool to execute the SPL over the last ~30 days. It splits result rows into true positives (matched on `cs_scenario_id` or attacker identity) and false positives.
7. **Tune.** If `fp_count` is above threshold, the runtime sends the design + SPL + sample FPs back to the Architect, which returns a refined design. Loop back to step 5.
8. **Approve.** When the detection catches the attack with FPs at or below threshold, the runtime pauses and asks a human for approval. This is the guardrail.
9. **Deploy.** On approval, the Deployer asks the LLM for a runbook (analyst description, triage steps, MITRE mapping), then writes the saved search via the SDK and the runbook to KV store. The dashboard updates.

## Why each tool is in this position

The split between MCP and SDK is deliberate:

- **MCP for reads and SPL-shaped work.** The MCP server is built around discovery + SPL execution + AI Assistant tools. Using it for the backtest and translation is the natural fit and earns honest credit for "uses MCP deeply."
- **SDK for writes.** The MCP server (in current versions) does not expose a generic "create-saved-search" tool. The Python SDK does. Using the SDK here is not a workaround — it is the supported path.

The same Splunk instance is the destination for both. The agent runtime is the single point of trust.

## Failure isolation

- **MCP unreachable.** The runtime's MCP client transparently falls back to the SDK for reads, so a broken MCP integration during development never blocks the loop.
- **AI Assistant tool unavailable.** The Translator falls back to an LLM-drafted SPL, validated by running it.
- **LLM returns malformed JSON.** Every agent call validates the response against a Pydantic schema and retries once with a repair instruction. If still bad, the orchestrator logs and exits cleanly.
- **Backtest exceeds MCP limits.** Time ranges are always bounded; aggregations always use `stats` or `tstats` to keep the result set under 1,000 rows.

## RBAC and security guardrails (the points most teams miss)

1. **Dedicated service account.** The MCP server connects under a role scoped to `index=counterspell` only. Even if an LLM prompt-injection attack succeeded, the blast radius is one sandbox index.
2. **OAuth 2.1 on MCP.** The MCP server (v1.1.0+) supports OAuth; configure it. Mention this in the write-up.
3. **Human-approval gate before deploy.** The Deployer never writes a saved search without explicit human approval. This is shown on screen in the demo.
4. **Iteration cap.** The orchestrator enforces a maximum number of tuning iterations (default 4) so a runaway loop cannot consume the model budget.
5. **No outbound actions.** The system never calls anything outside the Splunk instance. There is no firewall API, no SOAR webhook, no Slack post. This is intentional — it is what keeps the demo honest.

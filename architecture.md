# Counterspell Architecture

> This file is the architecture diagram of record. GitHub renders the Mermaid
> blocks below directly, so the diagram lives in the repo root as required.
> (Optional: export a PNG via the Mermaid CLI / VS Code preview for slides.)
>
> It shows the three things the submission asks for:
> 1. **How the app interacts with Splunk** — HEC inject, MCP `splunk_run_query`,
>    SDK `create_saved_search` / KV upsert, the in-Splunk custom command, and the
>    dashboard reading back.
> 2. **How the AI agents/models are integrated** — five agents driven by a
>    provider-agnostic OpenAI-compatible model; the Validator is deterministic.
> 3. **Data flow between services, APIs, and components** — the sequence diagram.

## System diagram

```mermaid
flowchart TB
  threat[/"Threat input<br/>(CVE · report · MITRE TID)"/]:::input

  subgraph entry["Entry points"]
    direction LR
    cli["CLI<br/>scripts/run_demo.py"]:::ui
    cmd["In-Splunk command<br/>counterspell (custom SPL command)"]:::ui
  end
  threat --> cli
  threat --> cmd

  subgraph runtime["Counterspell agent runtime · Python"]
    direction TB
    orch{{Orchestrator<br/><i>state · loop · approval gate</i>}}:::orch
    architect[Architect<br/>design + tune]:::agent
    redteam[Red-team<br/>synthetic attack]:::agent
    translator[Translator<br/>logic to SPL]:::agent
    validator[Validator<br/>TP / FP split · no LLM]:::deterministic
    deployer[Deployer<br/>runbook + saved search]:::agent

    orch --> architect
    orch --> redteam
    orch --> translator
    orch --> validator
    orch --> deployer
  end

  cli --> orch
  cmd ==>|subprocess → system Python<br/>runs the same orchestrator| orch

  llm[(Provider-agnostic LLM<br/>OpenAI-compatible · Groq / Ollama / Foundation-Sec)]:::ext
  mcp[(Splunk MCP Server v1.2.0<br/>JSON-RPC · RSA-encrypted scoped token)]:::ext
  sdk[(Splunk Python SDK)]:::ext

  architect -.->|complete_json| llm
  redteam -.->|complete_json| llm
  translator -.->|splunk_generate_spl<br/>if AI Assistant installed| mcp
  translator -.->|LLM fallback| llm
  deployer -.->|complete_json| llm

  redteam -->|HEC inject<br/>events tagged cs_scenario_id| sdk
  validator -->|run_splunk_query| mcp
  deployer -->|create_saved_search<br/>kv_upsert| sdk
  mcp -.->|SDK fallback on error| sdk

  sdk --> splunk
  mcp --> splunk

  splunk[(Splunk Enterprise<br/>index = counterspell)]:::splunk

  splunk --> dash[Counterspell dashboard<br/>FP curve · runbook · saved searches]:::ui

  orch -->|approval prompt| human([Human-approval gate]):::gate
  human -->|y| deployer

  classDef input fill:#1f2937,stroke:#9ca3af,color:#f9fafb
  classDef orch fill:#0ea5e9,stroke:#0369a1,color:#fff
  classDef agent fill:#7c3aed,stroke:#5b21b6,color:#fff
  classDef deterministic fill:#16a34a,stroke:#15803d,color:#fff
  classDef ext fill:#374151,stroke:#9ca3af,color:#f9fafb
  classDef splunk fill:#dc2626,stroke:#991b1b,color:#fff
  classDef ui fill:#f59e0b,stroke:#b45309,color:#000
  classDef gate fill:#fbbf24,stroke:#b45309,color:#000
```

## Data flow (the one-loop summary)

```mermaid
sequenceDiagram
  autonumber
  participant U as User
  participant O as Orchestrator
  participant A as Architect
  participant R as Red-team
  participant T as Translator
  participant V as Validator
  participant D as Deployer
  participant S as Splunk

  U->>O: paste threat
  O->>A: design(threat)
  A-->>O: DetectionDesign
  O->>R: generate(design)
  R-->>O: AttackScenario
  R->>S: HEC inject (stamps cs_scenario_id)
  loop iter ≤ max_iters
    O->>T: to_spl(design)
    T-->>O: SPL
    O->>V: backtest(spl, scenario)
    V->>S: run_splunk_query (MCP, SDK fallback)
    S-->>V: rows
    V-->>O: ValidationResult (tp_caught, fp_count)
    alt fp_count > threshold
      O->>A: tune(design, spl, result)
      A-->>O: refined DetectionDesign
    else converged
      Note over O: break
    end
  end
  O->>U: approval prompt
  U-->>O: y
  O->>D: document + deploy
  D->>S: create_saved_search · kv_upsert
  D-->>O: saved-search name
  O-->>U: summary (FP curve · deployed name · runbook)
```

## Failure isolation matrix

| Failure | Detected at | Fallback |
|---|---|---|
| MCP unreachable | `MCPClient.run_query` | Direct SDK `oneshot()` |
| AI Assistant `splunk_generate_spl` absent/empty | `Translator.to_spl` | LLM-drafted SPL via `complete_json(SplOutput)` (this is the path on a stock MCP install without the AI Assistant add-on) |
| LLM returns malformed JSON | `LLMClient.complete_json` | One repair-retry with the validation error in-prompt |
| Backtest result set too large | (design) | All SPL is `stats`/`tstats`-aggregated; rows < 1k |
| Loop fails to converge in `max_iters` | `Orchestrator.run` | Emit `incomplete`, return state without deploying |
| User declines deploy | `Orchestrator._confirm` | Emit `declined`, return state without writing |

## Why MCP for reads, SDK for writes

| Operation | Tool | Reason |
|---|---|---|
| `splunk_run_query` (backtest) | MCP | Every backtest runs through MCP; run logs record `used_mcp=true`. The MCP server is built for this. |
| `splunk_generate_spl` (translate) | MCP → LLM | Used when the AI Assistant for SPL add-on is installed; otherwise the Translator falls back to the LLM. |
| HEC inject (red-team events) | SDK | MCP server (v1.2.0) has no HEC tool; SDK is the supported path. |
| Saved-search create (the headline write) | SDK | MCP server exposes no generic "create knowledge object." |
| KV store upsert (runbook) | SDK | Direct REST via the SDK's auth context. |

Both clients hit the same Splunk instance under the same dedicated service
account scoped to `index=counterspell`. The agent runtime is the single point
of trust.

# Counterspell — pitch (for the Devpost write-up)

> One-paragraph version, for the Devpost long-text box.

**Counterspell turns a threat description into a deployed, zero-false-positive
Splunk detection in under four minutes.** Every SOC has the same bottleneck —
not reading alerts, but writing the detections that produce them. Detection
engineers cannot keep up with new threats, so coverage lags and the rules that
do exist are noisy. Counterspell is an autonomous detection engineer: five
specialized AI agents — Architect, Red-team, Translator, Validator, Deployer —
coordinate to design a detection, generate a synthetic attack to prove it
fires, backtest it against 30 days of historical data, tune false positives
out by themselves, pause for human approval, and ship the rule as a real,
scheduled, ES-ready saved search with a SOC runbook and MITRE-mapped
risk-based-alerting metadata. The headline visual is the false-positive count
dropping live across iterations (47 → 12 → 0) while the attack stays caught.
The headline *action* is real — no mock, no faked auto-remediate: Counterspell
writes to Splunk via the Python SDK and reads via the Splunk MCP Server,
under a dedicated service account scoped to a single sandbox index.

---

## Devpost form, section by section

### Inspiration

The detection-engineering bottleneck. Detection engineers take weeks to
ship a single rule, and the rules they ship are noisy. Every "AI SOC"
demo we saw automates the *triage* of alerts an engineer already wrote.
Nobody is automating the *writing*.

### What it does

Paste in a threat — a CVE, a Mandiant report, a MITRE technique — and
five agents collaborate to ship a deployed, validated detection in
minutes:

- **Architect** (OpenAI-compatible LLM) maps the threat to MITRE ATT&CK
  and designs a tunable detection.
- **Red-team** (LLM + Splunk HEC) generates a synthetic attack
  and injects it so the loop has a guaranteed true positive.
- **Translator** (Splunk AI Assistant via MCP when available, with LLM
  fallback) converts the design into SPL.
- **Validator** (pure Python — deterministic, no LLM) runs the SPL via
  MCP or the SDK fallback, splits result rows into TP and FP, returns a
  scored result.
- **Deployer** (LLM + Splunk SDK) writes the SOC runbook and
  creates the real ES-ready saved search.

The LLM seat is provider-agnostic: any OpenAI-compatible endpoint
(Splunk-hosted Foundation-Sec, Groq, Ollama, vLLM) — a config change,
not a code change.

**In our test environment, Counterspell turned three independent threat
descriptions into deployed zero-false-positive detections in under eight
minutes total.**

### How we built it

- **Splunk Python SDK** — performs the real saved-search write, the
  backtest searches, event ingestion, and KV-store runbook persistence.
- **MCP-first integration layer** — `run_splunk_query` backs the
  Validator and `saia_generate_spl` backs the Translator when the Splunk
  MCP Server is installed; both fall back transparently to the SDK / LLM
  (our demo environment runs the fallback path — enabling MCP is a
  config change, not a code change).
- **Provider-agnostic OpenAI-compatible model** — drives the Architect,
  Red-team, and Deployer agents; Splunk-hosted Foundation-Sec drops in
  via `.env`.
- **ES-ready deploys** — every deployed search carries notable-event +
  Risk-Based Alerting metadata + correlation-search tagging when
  Enterprise Security is installed, and ships as a plain scheduled saved
  search otherwise. ES users get a usable detection on day one.
- **Splunk app packaging** — a custom SPL command (`| counterspell
  threat="..."`) and a SimpleXML dashboard ship as
  `counterspell-0.1.0.tgz`; passes AppInspect.

### Challenges we ran into

Three real ones:

1. **JSON-locked output from the model.** Our solution: every
   agent call validates against a Pydantic schema and one-shot-retries
   with the validation error in the repair prompt. The
   [`LLMClient`](src/counterspell/llm_client.py) handles this in 80 lines
   and we have eight unit tests pinning the contract.
2. **The FP curve needed somewhere to drop from.** A first-pass naive
   detection on a vanilla benign baseline triggers zero false positives
   — no demo. We baked deliberate noise into the synthetic data
   generator (3% benign auth failures, 2% large legitimate transfers)
   so a naive design starts at 30–50 FPs and the tuning loop has work
   to do.
3. **MCP runtime + result-size limits.** All SPL is `stats`/`tstats`-
   aggregated; time ranges are bounded; the Validator never asks for
   more than a few hundred rows back. When MCP is unreachable, the
   client transparently falls back to the SDK so the demo never breaks.

### Accomplishments that we're proud of

- A **genuinely closed loop** — detect → design → backtest → tune →
  deploy, with a real write to Splunk that survives a UI refresh.
- A **visible magic moment** — the FP curve drop is what judges remember.
- A **guardrailed agent** — service account scoped to one sandbox
  index (OAuth 2.1 when MCP Server is enabled), human-approval gate
  enforced in code, iteration cap, no outbound actions.
- **ES-ready deploys** — notable + risk + correlation-search
  metadata attached when Enterprise Security is present, not just
  `saved_searches.create`.
- An **automatic MITRE ATT&CK Navigator coverage layer** generated from
  run logs, droppable into the public Navigator at
  https://mitre-attack.github.io/attack-navigator/.

### What we learned

The MCP server's design — scoped tools, OAuth, RBAC, transparent
fallback paths — makes it genuinely possible to give an LLM real write
access to Splunk without it being a bad idea. The blast radius of a
prompt injection is one sandbox index, by construction. That's a
materially different story than "we mock the write because we can't
trust the model."

### What's next

- **Live alert triage** — the natural downstream loop. Counterspell
  writes the rule; a sibling agent triages the resulting notables.
- **Multi-tenant** — each customer gets a per-tenant `counterspell_*`
  index and service account.
- **CDTSM observability variant** — the same loop, but the "threat"
  is an SLO violation and the "detection" is a saved search over
  application metrics.

### Built with

`python` · `splunk` · `splunk-sdk` · `splunk-mcp-server` · `foundation-sec` ·
`splunk-ai-assistant-for-spl` · `splunk-enterprise-security` ·
`risk-based-alerting` · `mitre-attack` · `pydantic` · `openai` · `ai-agents` ·
`cybersecurity` · `detection-engineering`

---

## The numbers (fill these in after final dry-run)

| Metric | Value |
|---|---|
| Threats in portfolio | 9 (3 headline + 6 extended) |
| Detections deployed end-to-end | _ / 9 |
| Total false positives at convergence (sum) | _ |
| Total tuning iterations across all runs | _ |
| End-to-end wall time per detection (avg) | _ min |
| Total wall time, all nine | _ min |
| MITRE techniques covered | 13+ |
| Sourcetypes exercised | 3 / 3 (cs:auth · cs:process · cs:network) |
| Lines of Python (excluding tests) | _ |
| Lines of tests | _ |
| Tests passing in CI | 41 / 41 |

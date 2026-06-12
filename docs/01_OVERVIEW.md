# 01 — Overview

## The one-liner

Paste in a threat report or a CVE, and a team of AI agents designs a detection, backtests it against real Splunk data, tunes out the false positives by itself, and ships a deployable, documented detection rule — collapsing weeks of detection-engineering work into minutes.

## The pitch (this is what you tell judges)

Every SOC has the same bottleneck: not reading alerts, but *writing the detections that produce them*. Detection engineers cannot keep up with new threats, so coverage lags and the rules that do exist are noisy. Counterspell is an autonomous detection engineer. Give it a threat — a Mandiant report, a CVE, a MITRE technique — and it reasons out the detection logic, writes the SPL, generates a synthetic attack to prove the rule fires, backtests against historical data to measure false positives, and iterates until the rule catches the attack with near-zero noise. Then it deploys the rule and writes its own documentation.

## Why this design wins the grand prize

- **It is the white space.** The crowded field will build "AI SOC analyst that triages alerts" — exactly what Foundation-Sec is marketed for. Counterspell automates the *upstream* problem nobody else touches: detection creation and tuning.
- **The action is REAL, not simulated.** The fatal flaw in most agentic-ops demos is a faked "auto-remediate." Counterspell's action is creating a saved search in Splunk — a fully supported, native write. Nothing is mocked.
- **It is genuinely multi-agent.** Five specialized agents (Architect, Translator, Red-team, Validator, Deployer) coordinate to close one loop. This hits the agent-orchestration judging bonus directly.
- **It has a visible magic moment.** The demo shows the false-positive count dropping live across iterations (e.g. 47 → 12 → 0) while the attack is still caught. Judges remember curves that drop on screen.
- **It is measurable.** Detections shipped, MITRE coverage added, false-positive rate driven to zero. Every judging criterion (implementation, design, impact, creativity) has a concrete hook.
- **It uses the platform deeply and honestly.** MCP Server for reads and SPL generation, AI Assistant for SPL translation, Hosted Models (Foundation-Sec) for reasoning, Python SDK for the real write, optionally packaged as a validated Splunk app.

## Scope: two pillars only

Build exactly these. A polished single loop beats five half-built features.

1. **The self-tuning detection loop.** Threat in → SPL detection out, backtested and FP-tuned against seeded data.
2. **The auto-documentation and deploy.** The agent writes the rule as a real saved search with MITRE mapping and a human-readable runbook entry.

### Explicitly OUT of scope

These can be mentioned as "future work" in the write-up but must not be built:
- Live alert triage
- SOAR / response actions (firewall changes, account lockouts, etc.)
- Multi-tenant operation
- Fine-tuning a custom model
- A custom ML classifier
- SOC + NOC convergence
- Slack/Jira/Confluence integrations

If you are tempted to add any of these, stop. Two pillars. Depth wins.

## What survives the brutal check

This idea has been pressure-tested against the obvious alternatives:

- **vs. "AI SOC analyst" (the crowd):** Counterspell is upstream — it creates the detections the analyst would otherwise be drowning in.
- **vs. AegisOps / Change Risk Autopilot:** AegisOps's headline action ("auto-rollback") is a mocked API call in a free trial. Counterspell's headline action is a real saved-search write.
- **vs. OmniGuard Nexus (the maximalist):** OmniGuard specs a four-agent swarm + SOC/NOC convergence + external firewall control + self-policing layer + full CI/CD. In ~18 days that produces pieces that half-work. Counterspell ships one loop that fully works.

The bet: a single working loop with a magic visible moment beats an impressive architecture diagram with mocked actions.

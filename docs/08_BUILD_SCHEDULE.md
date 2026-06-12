# 08 — Build Schedule

**Today:** May 28, 2026 · **Deadline:** June 15, 2026, 9:00 AM PDT · **Working days:** 18

This schedule assumes 2–3 engineers working part-time. A solo builder should compress to the bold-italic items and accept a smaller scope.

The guiding principle: **one tight end-to-end loop is the goal of week 1, polish is the goal of week 2, submission is the goal of week 3.** Never push code in the last 48 hours.

---

## Week 1 — Make the loop run end-to-end

### Days 1–2 (May 28–29) — Day-0 gate + environment

**Owner:** All

- [ ] Confirm eligibility in `#splunk-ai-hackathon` Slack
- [ ] Confirm hosted-model access path (Path A Splunk-hosted, or Path B self-hosted)
- [ ] Install Splunk Enterprise trial (60-day, on-prem)
- [ ] Install MCP Server, AI Assistant for SPL, AI Toolkit from Splunkbase
- [ ] Create `counterspell` index
- [ ] Create HEC token (`counterspell_hec`)
- [ ] Create dedicated MCP service account, scope role to `index=counterspell` only
- [ ] If Path B: pull Foundation-Sec 8B GGUF and stand up Ollama/vLLM
- [ ] Verify: can hit the LLM endpoint with a curl POST
- [ ] Verify: can write a test saved search via the SDK and see it in the UI

**Definition of done:** the loop's external dependencies — Splunk, MCP, LLM, HEC — are all reachable from a single laptop with one command each.

### Days 3–4 (May 30–31) — Data + client layer

**Owner:** 1 engineer

- [ ] Write `config.py`, `schemas.py`, `prompts.py`
- [ ] Write `llm_client.py` and test JSON-validation-and-retry with a trivial prompt
- [ ] Write `splunk_client.py` and verify oneshot search returns results
- [ ] Write `generate_synthetic_data.py` and seed 30 days of data
- [ ] Run the data acceptance checks from `06_DATA_MODEL.md`

**Definition of done:** `python data/generate_synthetic_data.py` populates the index; you can search it from the Splunk UI and see realistic distributions.

### Days 5–7 (Jun 1–3) — Core loop on ONE threat

**Owner:** 2 engineers in parallel

- [ ] Write `mcp_client.py` with SDK fallback; one `run_splunk_query` call works
- [ ] Write `architect.py` — `design()` only, no tuning yet
- [ ] Write `translator.py` — LLM fallback path first, MCP path second
- [ ] Write `validator.py` — deterministic TP/FP split
- [ ] Write a minimal `orchestrator.py` — single pass, no loop, no deploy
- [ ] Run it on `threats/t1048_exfil.md`. See a real `ValidationResult` come back with a real FP count.

**Definition of done:** end-to-end single pass on one threat returns a non-trivial result. The hardest part of the project is done.

---

## Week 2 — Make the loop self-tune, real-deploy, and demo-worthy

### Days 8–9 (Jun 4–5) — The self-tuning loop + Red-team

**Owner:** 1 engineer on tuning, 1 on red-team

- [ ] Add `tune()` to the Architect
- [ ] Write `redteam.py` — generate `AttackScenario` and inject via HEC
- [ ] Extend the orchestrator with the loop (max 4 iterations)
- [ ] Verify on `t1048_exfil`: FP count drops across iterations
- [ ] Tune prompts and data if the curve doesn't move (per `05_PROMPT_LIBRARY.md`)

**Definition of done:** running the orchestrator on the exfil threat shows a clear FP curve dropping toward zero. **This is the magic-moment milestone — if it lands here, the demo lands.**

### Days 10–11 (Jun 6–7) — Real deploy + the runbook

**Owner:** 1 engineer

- [ ] Write `deployer.py` — doc generation and the SDK saved-search write
- [ ] Add the human-approval gate to the orchestrator
- [ ] Add KV store collection `counterspell_runbook`; write entries on deploy
- [ ] Verify: after a successful run + approval, the saved search appears in Splunk's UI, can be opened, and runs cleanly

**Definition of done:** a complete run from threat input to a real deployed saved search, with explicit approval shown on screen.

### Days 12–13 (Jun 8–9) — In-Splunk UX

**Owner:** 1 engineer

- [ ] Write the custom command `splunk_app/bin/counterspell.py` (wraps the orchestrator)
- [ ] Write `app.conf`, `commands.conf`
- [ ] Build the SimpleXML dashboard: threat input, live progress text, FP curve chart, runbook list
- [ ] Verify `\| counterspell threat="..."` works from the Splunk search bar

**Definition of done:** an analyst can use Counterspell entirely from inside Splunk without seeing your Python.

### Day 14 (Jun 10) — Second and third threats; polish

**Owner:** All

- [ ] Run the loop on `t1110_bruteforce.md` — fix any generalization issues
- [ ] Optionally add a third threat (a recent CVE description)
- [ ] Tighten prompts, data, thresholds wherever weak
- [ ] Write `scripts/run_demo.py` — the exact CLI you will use to record the video

**Definition of done:** Counterspell handles three distinct threats cleanly; the demo CLI prints a satisfying progress narrative.

---

## Week 3 — Submit

### Days 15–16 (Jun 11–12) — Package and polish

**Owner:** All

- [ ] Export the Mermaid diagram to `architecture.png` at the repo root
- [ ] Write the final `README.md` (intro, doc index, quickstart, Day-0 gate prominent)
- [ ] Validate `splunk_app/` with AppInspect; fix any warnings
- [ ] Generate the `.tgz` app artifact
- [ ] Run end-to-end on all three threats one more time; capture FP curves

**Definition of done:** everything passes AppInspect; the repo is clean and a stranger could clone and run it from the README alone.

### Day 17 (Jun 13) — Record the video

**Owner:** Whoever speaks best

- [ ] Record the 3-minute demo per `09_DEMO_SCRIPT.md`
- [ ] Re-record if the FP curve doesn't visibly drop on screen — this is the one shot that has to land
- [ ] Upload to YouTube as unlisted
- [ ] Test the link from a private browser

**Definition of done:** the video shows the FP curve dropping, the deployed saved search appearing in Splunk, and the runbook being written. Total runtime ≤ 3:00.

### Day 18 (Jun 14, **submit by end of Jun 14 — do not touch Jun 15**)

**Owner:** Team lead

- [ ] Draft the Devpost write-up: problem + metric in the opening line, every Splunk capability named, track = Security
- [ ] Attach video, repo URL, `architecture.png`, `.tgz` app
- [ ] Re-read against the Official Rules (which by now will have published)
- [ ] Submit

**Definition of done:** submitted ≥ 12 hours before the 9:00 AM PDT deadline on June 15. **Never push to the actual deadline — Devpost gets hammered in the final hour every time.**

---

## Buffer principle

Every milestone above has at least half a day of buffer baked in. If you're on schedule by Jun 11 (end of week 2), you've effectively got two free days. Use them on demo polish, not on adding scope.

## Red-flag triggers (stop-the-line moments)

| Symptom | Day-by trigger | Response |
|---|---|---|
| LLM endpoint not reachable | End of Day 2 | Switch hosted-model path (A↔B); do not try to fix the unreachable one |
| First end-to-end pass doesn't run | End of Day 7 | Cut Translator to LLM-only (drop the MCP primary path); reassess scope |
| FP curve will not drop | End of Day 9 | Stop tuning prompts; enrich the data generator with more realistic near-miss noise |
| Splunk app won't validate | End of Day 16 | Submit without the app; the agent runtime + dashboard via REST is enough |

## If you fall a week behind

If by Jun 4 you do not have an end-to-end single pass working, cut hard:

- Drop the MCP server entirely; use only the Python SDK. The write-up still mentions MCP as "future work."
- Drop the in-Splunk dashboard; build a minimal terminal output that shows the FP curve as ASCII bars.
- Keep only one demo threat.

A 2-minute demo on one threat with a real FP curve and a real saved-search write beats no submission.

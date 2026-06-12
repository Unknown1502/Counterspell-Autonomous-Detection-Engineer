# 09 — Demo Script and Submission Checklist

The video is half your score. It is what every judge actually watches. Treat it as the primary artifact, not as a recording of "the project."

---

## Demo script — 3:00 total

Length is a hard ceiling. Practice with a stopwatch. Re-record until the FP curve drops on screen with at least 5 seconds of dwell time on it.

### Beat 1 — Hook (0:00 – 0:20)

**Visual:** One title slide. Black background. Large text:

> **Counterspell**
> *An autonomous detection engineer for Splunk*

**Voiceover:**
> "Every SOC has the same bottleneck. Not reading alerts — *writing the detections that produce them*. It takes detection engineers weeks to ship a single rule, and the rules they do ship are noisy. Counterspell is an autonomous detection engineer. Give it a threat. It does the rest."

### Beat 2 — Paste the threat (0:20 – 0:50)

**Visual:** The Counterspell dashboard inside Splunk. A text box. Paste a threat description (the exfiltration scenario from `threats/t1048_exfil.md`).

**On-screen:** the Architect agent's reasoning appears live — "extracted technique: T1048", "data source: cs:network", "logic: large outbound bytes over alternative port from one internal IP to one external IP".

**Voiceover:**
> "Here's a real threat — data exfiltration over an alternative protocol. I paste it in. The Architect agent — running on Foundation-Sec, Splunk's hosted security model — reasons through what behavior we'd actually see in our data and maps it to MITRE T1048."

### Beat 3 — Write and prove (0:50 – 1:30)

**Visual:** The Translator agent produces SPL — it appears in a code block on screen. The Red-team agent panel shows "injecting 18 synthetic attack events". Then the Validator panel: "✅ caught the attack — ⚠️ 47 false positives".

**Voiceover:**
> "The Translator turns that logic into SPL using the Splunk AI Assistant. The Red-team agent generates a small synthetic attack and injects it into our index so we have a guaranteed true positive. The Validator runs the detection against thirty days of historical data. It caught the attack — but it also fired on forty-seven benign events. That's not a usable rule yet."

### Beat 4 — The magic moment (1:30 – 2:20)

**Visual:** A live-updating bar chart or large number. The FP count.

- Iteration 1: **47 FPs** (red)
- Iteration 2: **12 FPs** (orange)
- Iteration 3: **0 FPs, attack caught** (green)

Each iteration takes a few seconds to render. Hold on the final "0" for five full seconds.

**Voiceover (slow, deliberate):**
> "Here's what makes Counterspell different. The Validator sends those false positives back to the Architect, which sees specifically what benign patterns it's wrongly flagging — and tightens the detection. Watch the false-positive count drop. Forty-seven. Twelve. Zero. Attack still caught. No human touched this loop."

### Beat 5 — Ship it (2:20 – 2:50)

**Visual:** A "Deploy?" prompt appears — *human-approval gate*. Click "Approve." The saved search appears in Splunk's Settings → Searches list. The runbook entry appears in the dashboard with MITRE mapping and triage steps.

**Voiceover:**
> "Counterspell pauses for human approval — this is an agent that can write to your Splunk instance, so a human always says yes. On approval, the Deployer creates a real, scheduled saved search through the Splunk Python SDK — that's the saved search appearing right there in Settings — and writes its own runbook to the KV store."

### Beat 6 — Close (2:50 – 3:00)

**Visual:** Back to the title slide, with a single line of stats added underneath:
> **3 detections shipped. 0 false positives. 8 minutes.**

**Voiceover:**
> "Counterspell. The work that used to take a detection engineer a week, in three minutes. Built on Splunk's MCP server, hosted Foundation-Sec model, AI Assistant for SPL, and the Python SDK. Real writes. No mocks."

---

## What makes or breaks the video

| Make | Break |
|---|---|
| The FP curve visibly drops on screen | Showing the FP curve only in narration |
| The saved search appears in Splunk's real UI | Mocking the saved search in your app's UI |
| The approval prompt is shown and clicked | Auto-deploying without showing the gate |
| Under 3 minutes | Over 3 minutes |
| One clean threat scenario | Three half-explained scenarios |
| Voiceover is slow and confident | Reading at 1.5x speed |
| No live coding, no terminals | Showing your IDE |

---

## Judge Q&A — prepared answers

The video sets up the questions; Q&A is where projects are won or lost. Rehearse
these out loud. The pattern that wins: **admit the gap precisely, then show you
understand it better than the asker expected.** Hedging or over-claiming is what
loses trust.

### Q: "Does this work on real customer data, or only the noise you planted?"

This is the single most likely make-or-break question. Memorize this:

> "On real data, three things get harder: ground-truth labeling, the messiness
> of benign traffic, and reaching literal zero false positives. What we've
> proven is that the **autonomous loop** — design, inject, backtest, tune,
> deploy — works end to end against labeled data, and that the rule it produces
> **generalizes to noise it was never tuned on**. [Run `check_generalization.py`
> on screen.] The path to production is replacing our synthetic ground truth
> with analyst-confirmed labels — which is exactly the human-in-the-loop our
> approval gate already models. The architecture doesn't change; only the source
> of truth does."

Then point at the green `✓ GENERALIZES` result. That single artifact converts the
critique into a strength. Full reasoning: [docs/06_DATA_MODEL.md](06_DATA_MODEL.md#synthetic-vs-real-life--the-honest-boundary).

### Q: "Why synthetic data at all?"

> "Three reasons. One — real SOC logs are confidential and can't go in a public
> repo, so synthetic is the only legal option, and every detection demo uses it.
> Two — the Validator needs deterministic ground truth to compute a real FP
> count; we stamp each attack event with a scenario ID so TP/FP is provable, not
> an LLM guess. Three — reproducibility: same seed, same curve, recordable demo."

### Q: "Aren't the agents just thin wrappers around prompts?"

> "The Architect, Red-team, and Deployer are LLM agents; the Validator is
> deliberately pure Python — we do **not** let a model judge true vs. false
> positive, because that's the one thing that has to be deterministic for the FP
> curve to be trustworthy. The value isn't any single agent — it's the closed
> loop with a deterministic scorer and a human gate. That's the part nobody else
> automates: everyone automates triaging alerts an engineer already wrote; we
> automate writing the detection."

### Q: "What model is this actually running on?"

Answer **truthfully** based on what you ran:

- If on the real Splunk-hosted Foundation-Sec endpoint: say "Foundation-Sec via
  an OpenAI-compatible endpoint."
- If on Ollama / self-hosted: say **"a self-hosted, OpenAI-compatible
  security-capable model — our client is provider-agnostic, so swapping in
  Splunk's hosted Foundation-Sec is a config change, not a code change."**

Do **not** claim Foundation-Sec if you didn't run it. The provider-agnostic
framing is honest and still strong. See the voiceover note in Beat 6 below.

> ⚠️ **Voiceover accuracy:** Beats 6 and the "How we built it" list below say
> "Foundation-Sec." If you recorded on Ollama, change those lines to the
> provider-agnostic phrasing above. An over-claim a judge can't verify is the
> fastest way to lose the technical-implementation score.

### Q: "What stops the agent from doing damage with write access?"

> "Four guardrails, enforced in code. A dedicated service account scoped to one
> index — even a successful prompt injection has a one-index blast radius. A
> human-approval gate before any write, shown on screen. An iteration cap. And
> no outbound actions — the only thing it writes to is the same Splunk it reads
> from."

---

## Optional demo beat — the generalization proof

If you have 15 extra seconds, add this right after Beat 5 (deploy):

**Visual:** terminal runs `python scripts/check_generalization.py`. A green
`✓ GENERALIZES — fired on 0 holdout events` appears.

**Voiceover:**
> "And here's the part that matters: we run the deployed rule against a second
> set of benign traffic it was *never tuned on*. Zero false positives. It
> learned the pattern, not the noise we planted."

This is the strongest possible pre-emption of the "is it theater?" critique — and
it's better shown than argued.

---

## Submission write-up structure (Devpost)

Devpost gives you a long-form text area. Use this structure:

### 1. Inspiration (2 sentences)
The detection-engineering bottleneck. Specifically: SOC teams can't write rules fast enough and the ones they write are noisy.

### 2. What it does (2–3 sentences)
The one-liner from `01_OVERVIEW.md`, followed by one concrete number: *"In our test environment, Counterspell turned a threat description into a deployed, zero-false-positive detection in under four minutes."*

### 3. How we built it (bullet list)
Name every Splunk capability with one line each:
- **Splunk MCP Server** — runs the validator's backtests and translates detection logic to SPL via the AI Assistant tools
- **Splunk AI Assistant for SPL** — `saia_generate_spl` and `saia_optimize_spl` power the Translator agent
- **Splunk Hosted Models — Foundation-Sec** — drives the Architect, Red-team, and Deployer agents
- **Splunk Python SDK** — performs the real saved-search write and KV-store runbook persistence
- **Splunk app packaging** — the `counterspell_app` ships a custom SPL command and dashboard; passes AppInspect

### 4. Challenges (1 paragraph)
Honest version: getting JSON-locked output reliably from Foundation-Sec, designing benign noise into the data generator so the FP curve has somewhere to drop from, and respecting the MCP server's runtime and result-size limits in the Validator.

### 5. Accomplishments (3 bullets)
- A genuinely closed loop: detect → design → backtest → tune → deploy, with a real write
- A visible magic moment (the FP curve)
- A guardrailed agent: dedicated service account, RBAC-scoped role, human-approval gate, iteration cap

### 6. What we learned (1 paragraph)
Something specific to Foundation-Sec or to the MCP server, not generic. E.g.: *"The MCP server's design — scoped tools, OAuth, RBAC — makes it possible to give an LLM real write access without it being a bad idea."*

### 7. What's next (3 bullets)
Live alert triage. Multi-tenant. The CDTSM observability variant of the same loop. (These are explicitly out of scope for v1.)

### 8. Built with (tag list)
`python` `splunk` `splunk-sdk` `mcp` `foundation-sec` `ai-assistant` `ai-agents` `cybersecurity` `mitre-attack`

---

## Final submission checklist

The night before you submit (end of Day 17 / morning of Day 18):

### Technical
- [ ] All three demo threats run cleanly end-to-end
- [ ] The saved searches Counterspell deployed are visible in Splunk's Settings → Searches
- [ ] The runbook collection in KV store has entries for each deployed detection
- [ ] `splunk_app/` passes AppInspect with no errors
- [ ] `architecture.png` is at the repo root
- [ ] README quickstart works from a clean clone

### Submission artifacts
- [ ] Video uploaded to YouTube as **unlisted** (not private); link tested in a private browser
- [ ] Video is ≤ 3:00 long
- [ ] The FP curve dropping is clearly visible on screen
- [ ] Repo is public on GitHub
- [ ] OSS license file in the repo

### Devpost form
- [ ] Track selected: **Security**
- [ ] Write-up follows the 8-section structure above
- [ ] All Splunk capabilities used are named
- [ ] First sentence of the write-up names the problem and includes one concrete number
- [ ] Team members all added to the submission

### Process
- [ ] Submitted **before end of Day 18 (June 14)**, not on June 15
- [ ] Submission confirmation email received and saved
- [ ] Done. Go to sleep.

---

## One last note

The single highest-leverage activity in the last week is not writing more code. It is re-recording the video until the FP curve drops convincingly on screen. If you have eight free hours in the final stretch, spend six on the video and two on the write-up. Do not spend them on features.

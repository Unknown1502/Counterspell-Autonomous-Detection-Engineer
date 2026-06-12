# Counterspell — Setup to First Real Run (Windows)

This is the exact, ordered path from a clean Windows machine to a recorded
`47 → 12 → 0` run with a real saved search written to a real Splunk. Follow it
top to bottom. Each step ends with a check you can confirm before moving on.

> **The single goal:** get ONE real end-to-end run on screen. Everything in the
> pitch rests on the FP curve dropping live. Until that has happened once on
> real infra, nothing else matters. This guide gets you there.

---

## 0. What you need (and what's optional)

| Component | Required? | Why |
|---|---|---|
| Splunk Enterprise (free trial, local) | **Yes** | The index, HEC, saved-search write |
| HEC token | **Yes** | Seeds baseline data + injects the red-team attack |
| splunkd auth token | **Yes** | SDK reads/writes |
| Ollama + a local model | **Yes** (recommended LLM path) | Drives Architect/Red-team/Deployer — free, local, no Foundation-Sec dependency |
| Splunk MCP Server | Optional | Earns judging credit; SDK fallback works without it |
| Splunk AI Assistant for SPL | Optional | Translator primary path; LLM fallback works without it |
| Splunk Enterprise Security | Optional | notable/risk/correlation enrichment; deploy degrades to a plain scheduled search without it |

**Decision already made for this project:** local Splunk + **Ollama** for the
model. That removes the Foundation-Sec dependency entirely — the biggest single
point of failure in the original plan.

---

## 1. Install Splunk Enterprise (local trial)

1. Download Splunk Enterprise for Windows: https://www.splunk.com/en_us/download/splunk-enterprise.html
2. Install (defaults are fine). It runs at **https://localhost:8000** (web),
   management on **8089**.
3. Set an admin password you'll remember during install.

**Check:** open https://localhost:8000 and log in.

---

## 2. Create the `counterspell` index

Splunk Web → **Settings → Indexes → New Index**
- Index name: `counterspell`
- Everything else default → Save.

**Check:** the index appears in the Indexes list.

---

## 3. Create the HEC token

Splunk Web → **Settings → Data inputs → HTTP Event Collector**

First, enable HEC globally: **Global Settings** → All Tokens = **Enabled**,
confirm HTTP Port = **8088**, **uncheck** "Enable SSL" only if you want plain
HTTP (this guide assumes SSL on, which matches the default `https://...:8088`).

Then **New Token**:
- Name: `counterspell_hec`
- Source type: leave automatic
- **Allowed indexes:** `counterspell`
- **Default index:** `counterspell`
- Save and **copy the token value** (you won't see it again).

**Check:** the token is listed and **Enabled**.

---

## 4. Create the splunkd auth token

Splunk Web → **Settings → Tokens** → enable token auth if prompted →
**New Token**
- User: `admin` (or a dedicated `svc_counterspell` user scoped to
  `index=counterspell` — better for the security story in your pitch)
- Audience: `counterspell`
- Expiration: set it past your demo date
- Save and **copy the token**.

> **Pitch bonus:** create a `svc_counterspell` user with a custom role whose
> search filter is `index=counterspell` and that can only write saved searches.
> Then your "one-index blast radius" guardrail claim is literally true, not
> aspirational. Settings → Access controls → Roles → New Role.

**Check:** you have two secrets copied — the HEC token and the auth token.

---

## 5. Install Ollama + pull a model

1. Install Ollama for Windows: https://ollama.com/download
2. In a terminal:
   ```powershell
   ollama serve            # leave running (or it runs as a service)
   ```
3. Pull a model. Foundation-Sec may not be on Ollama; use a capable
   general/instruct model — it produces good SPL for this task:
   ```powershell
   ollama pull llama3.1:8b
   # alternatives that also work well:
   #   ollama pull qwen2.5:7b-instruct
   #   ollama pull mistral-nemo
   ```

**Check:**
```powershell
(Invoke-WebRequest http://localhost:11434/v1/models -UseBasicParsing).Content
```
should list your pulled model.

> **On the "Foundation-Sec" claim:** if you cannot get the real Splunk-hosted
> Foundation-Sec endpoint, do NOT claim it in the video. Say "an
> OpenAI-compatible security-capable model (self-hosted)" — your `llm_client.py`
> is provider-agnostic, which is the honest and defensible framing. If you DO
> get Foundation-Sec, just set `LLM_BASE_URL`/`LLM_MODEL` to it; no code change.

---

## 6. Install Python dependencies

```powershell
cd "c:\Users\prajw\OneDrive\Desktop\Splunk Agentic Ops Hackathon\counterspell"
python -m pip install -r requirements.txt
python -m pip install -e .       # makes `counterspell` importable everywhere
```

**Check:**
```powershell
python -c "import splunklib, openai, pydantic, rich; print('deps OK')"
```

---

## 7. Configure `.env`

```powershell
Copy-Item .env.example .env
notepad .env
```

Fill in:
```dotenv
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_TOKEN=<the auth token from step 4>

SPLUNK_HEC_URL=https://localhost:8088/services/collector/event
SPLUNK_HEC_TOKEN=<the HEC token from step 3>

# Leave MCP empty for now (SDK fallback). Fill later if you install MCP Server.
MCP_URL=
MCP_TOKEN=

LLM_BASE_URL=http://localhost:11434/v1
LLM_API_KEY=ollama          # any non-empty string; Ollama ignores it
LLM_MODEL=llama3.1:8b       # MUST match what you pulled in step 5
```

> If you turned SSL **off** on HEC in step 3, change the HEC URL to
> `http://localhost:8088/...`.

---

## 8. Verify the whole environment (the Day-0 gate)

```powershell
python scripts/verify_environment.py
```

This now checks, in order: `.env` secrets → Splunk SDK connect → index exists →
HEC accepts an event → MCP (optional) → LLM responds → **ES present? (optional)**
→ **baseline data present?**. Fix anything red before continuing. The ES and
data checks are warnings, not blockers.

**Check:** "All required checks passed."

---

## 9. Seed ~30 days of baseline data (one-time, ~2–3 min)

```powershell
# Optional: fix the seed so the baseline is byte-identical between takes.
$env:COUNTERSPELL_SEED = "1337"
python data/generate_synthetic_data.py
```

This now seeds **two** classes of noise:
- the **primary noise** the tuning loop tunes against (3% auth failures, 2%
  large transfers, benign beacons, backup bursts, legit encoded PowerShell);
- the **holdout generalization set** (`cs_holdout=true`) the loop *never* sees —
  used in step 12 to prove the rule generalizes.

**Check:** the script prints non-zero counts for auth/process/network **and** a
`holdout` line. Then:
```powershell
python scripts/check_data_acceptance.py
```

---

## 10. Do a throwaway warm-up run

The first LLM call is slow (model load). Warm it so the recorded run is fast:

```powershell
python scripts/run_demo.py --threat threats/t1048_exfil.md --yes
```

Watch the output. You should see the curve drop and a deploy. If it reports
`incomplete`, see **Troubleshooting** below — but the hardening (best-result
tracking, red-team repair, search-failure recovery, indexing settle) is designed
to make this converge on a real instance.

**Check:** a saved search named `Counterspell - ...` exists at
**Settings → Searches, reports, and alerts** in Splunk Web.

---

## 11. The real run (record this one)

```powershell
python scripts/run_demo.py --threat threats/t1048_exfil.md
```

It pauses at the approval gate. On screen:
1. Show the FP curve dropping (`47 → 12 → 0` or similar — real numbers).
2. Type `y` at the approval prompt **on camera**.
3. Cut to Splunk Web → Settings → Searches and show the new saved search.

> Hold on the "0" for 5+ seconds. That dwell is the moment judges remember.

---

## 12. The generalization proof (your answer to "is this just theater?")

Immediately after the run converges and deploys:

```powershell
python scripts/check_generalization.py
```

It runs the **deployed** rule against the holdout noise it was never tuned on.
A green `✓ GENERALIZES — fired on 0 holdout events` is your on-camera rebuttal
to "would this work on real data, or only on noise you planted?" Show this. It
converts your biggest weakness into a strength.

---

## 13. Fill in the real metrics

After your real runs, fill the table in [PITCH.md](PITCH.md#L133) with actual
numbers (FP curves, wall time, iterations). An empty table reads as "never ran."

---

## Troubleshooting

**`incomplete` — the loop never hit 0 FPs.**
- The LLM may need a stronger model. Try `qwen2.5:7b-instruct` or a 14B model.
- For resilience, set `allow_best_effort: true` in `config.yaml`. The loop then
  deploys the lowest-FP iteration it reached instead of giving up. The deployed
  rule is always the best iteration, never just the last.
- Confirm step 9 actually seeded data: an empty index → curve starts at 0 →
  no story. `verify_environment.py`'s data check warns about this.

**`tp_caught` is False every iteration.**
- The red-team repair forces the attack into the design's key fields + a recent
  window, so this should be rare. If it persists, the LLM's SPL may not match
  the injected fields — check the SPL printed in the backtest panel.

**Saved-search create fails / no ES actions.**
- Expected on a vanilla trial without Enterprise Security. The deployer now
  retries automatically without ES metadata and ships a plain scheduled search.
  The KV runbook records `es_enabled=false` so you never over-claim ES.

**HEC 403 / events not searchable.**
- Token not scoped to `counterspell`, or HEC disabled globally. Re-check step 3.
- SSL mismatch: `https` URL vs SSL disabled (or vice versa).

**LLM returns invalid JSON.**
- `llm_client.py` already one-shot-retries with the validation error. If a model
  keeps failing, it's too small/weak — switch models.

**pytest won't collect (eth_typing / web3 error).**
- An unrelated global plugin is broken. Run tests with:
  ```powershell
  python -m pytest -p no:ethereum tests/
  ```

---

## What changed in this hardening pass (so you can speak to it)

All of these close gaps that the mock-based tests previously hid:

1. **Search failures no longer crash the demo** — a bad LLM-generated SPL becomes
   a recoverable "not caught" result the tune loop fixes next iteration.
2. **TP/FP attribution is value-exact**, not substring-on-a-blob — a benign
   `count=4799` can no longer be mistaken for attacker IP `...99`.
3. **Red-team output is repaired** to always carry the attacker entity, the
   design's key fields, and a recent in-window timestamp — so the attack is
   always catchable and reproducible.
4. **HEC indexing settle** — the loop waits until the injected attack is
   searchable before the first backtest, killing the timing coin-flip.
5. **Best-result convergence** — deploys the lowest-FP iteration, with an
   optional best-effort mode so a hard threat still ships a usable rule.
6. **ES metadata degrades gracefully** — deploy always succeeds; ES enrichment
   is applied only when ES is actually installed, and never over-claimed.
7. **Holdout generalization set + proof script** — the rule is tested against
   noise it was never tuned on, on camera.

Tests: **74 passing**, including 12 new ones that pin these exact contracts
(not mocks of them).

"""LLM prompt templates used by every Counterspell agent."""

SHARED_CONTEXT = """You operate inside Counterspell, an autonomous detection-engineering system for Splunk.
The only data available is in index="counterspell" with these sourcetypes and fields:

  cs:auth     -> _time, user, src_ip, host, action(success|failure), app
  cs:process  -> _time, host, user, process_name, parent_process, cmdline
  cs:network  -> _time, src_ip, dest_ip, dest_port, bytes_out, bytes_in, protocol

The data is ~30 days of mostly-benign baseline activity. The benign "noise" is
INDEPENDENT and SCATTERED: e.g. occasional large legitimate transfers go to
random destinations on random ports — they do NOT repeat to the same
destination. A real attack, by contrast, is a CONCENTRATED burst: the same
source hits the same destination/port many times in a short window.

Rules:
- Only reference the sourcetypes and fields listed above. Never invent fields.
- All SPL must begin with: search index="counterspell"
- Do NOT put earliest=/latest= time terms in the SPL — the backtest sets the
  time range for you over the full baseline window.
- Prefer stats/tstats aggregation; each result row = one detection hit.
- Return ONLY the JSON object requested. No explanations, no markdown code fences."""


ARCHITECT_DESIGN = """{shared}

You are a senior detection engineer. Given a threat description, design ONE Splunk
detection. Map it to MITRE ATT&CK and specify concrete, tunable detection logic.

This is the FIRST pass and it has ONE job: maximize recall. It MUST catch the
attack and it MUST ALSO fire on a meaningful amount of benign activity (dozens
of false positives) so the later tuning pass has something to remove. A first
pass that produces few or zero false positives is a FAILURE — the tuning loop
has nothing to show.

Hard requirements for this first design:
- Exactly ONE qualifying condition, chosen to be as PERMISSIVE as possible while
  still matching the technique. For exfil/volume techniques: a non-standard
  destination port (anything not in 80,443,22,53,3389) AND bytes_out over a LOW
  threshold (use 50 MB — do NOT go higher).
- Aggregate per entity with a simple `stats sum(bytes_out) as total ... by
  src_ip dest_ip` and threshold the SUM at a LOW value (~50 MB).
- DO NOT add ANY of these on the first pass: event-count / burst / clustering
  requirements, time-window bucketing, average-size floors, allowlists, or
  multiple AND-ed conditions. Those are for tuning, not now.
- Set thresholds at the LOWEST end that still matches the technique.
The benign baseline contains many one-off large legitimate transfers; a loose
rule like the above will correctly flag ~dozens of them as false positives.
That is the desired outcome of pass one.

Return a JSON object with exactly these keys:
{{
  "title": "short detection name",
  "mitre_techniques": ["Txxxx"],
  "rationale": "1-2 sentences",
  "sourcetypes": ["cs:auth"],
  "key_fields": ["field"],
  "logic": "plain-English detection logic",
  "thresholds": {{"name": 0}},
  "false_positive_notes": "benign patterns that might trip this"
}}

Threat to detect:
---
{threat_text}
---"""


ARCHITECT_TUNE = """{shared}

You are tuning an existing detection to REDUCE false positives while STILL catching
the true attack. Return the SAME JSON schema.

RULE #1: NEVER lose the true positive. If `true positive caught` is true now, it
MUST stay true. Tighten GRADUALLY — make ONE incremental change per pass, not
several at once. Over-tightening that drops the attack is worse than leaving a
few false positives.

The most powerful lever: the true attack is a CONCENTRATED burst (the same source
repeatedly hits the same destination/port MANY times, tens of MB each, hundreds
of MB total), while the benign false positives are one-off, scattered events to
different destinations. So the single highest-value tightening is to require that
the same src→dest/port repeats (e.g. 3+ events in a short window) — this removes
the scattered one-off benign transfers while keeping the burst. Apply that ONE
change first. Only if false positives remain should you, on a later pass, also
raise the volume threshold or exclude a clearly-benign value from the sample FPs.
Keep thresholds BELOW the attack's own size (the attack sends ~250 MB per event,
hundreds of MB total, in a tight cluster) so you never tune past it.

Current design:
{design_json}

Current SPL:
{spl}

Backtest result:
- true positive caught: {tp_caught}
- false positives: {fp_count}
- sample false-positive events:
{sample_fps}

Produce a refined design that keeps the true positive but lowers false positives."""


TRANSLATOR_FALLBACK = """{shared}

Convert the detection logic into a single valid SPL search starting with:
search index="counterspell"
Use stats/tstats aggregation. Each result row = one detection hit with entity + _time.

Return JSON: {{"spl": "<the full SPL>"}}

Detection design:
{design_json}"""


REDTEAM_GENERATE = """{shared}

You are a red-team operator. Generate a small, realistic set of synthetic events that
exhibit the given MITRE technique. Use one attacker entity. Spread events over a
short recent window.

Return JSON:
{{
  "scenario_id": "kebab-case-unique-id",
  "attacker": {{"user": "...", "src_ip": "...", "host": "..."}},
  "window": {{"earliest": "ISO8601", "latest": "ISO8601"}},
  "events": [{{"sourcetype": "cs:auth", "fields": {{}}}}]
}}

Technique(s): {mitre_techniques}
Detection logic to satisfy: {logic}
Generate between 5 and 30 events."""


DEPLOYER_DOC = """{shared}

Document this finished, validated detection for a SOC runbook. Be concise.
Return JSON:
{{
  "saved_search_name": "Counterspell - <title>",
  "description": "what it detects, 1-2 sentences",
  "mitre_techniques": ["Txxxx"],
  "triage_steps": ["analyst step 1", "step 2"],
  "validation_summary": "caught simulated attack with N FPs after K iterations"
}}

Final design: {design_json}
Final SPL: {spl}
Validation: tp_caught={tp_caught}, final fp_count={fp_count}, iterations={iterations}"""

# 02 — Day-0 Gate

Two facts are unconfirmed and gate the entire project. Resolve them in the first 24 hours.

---

## Gate 1: Eligibility

**The question:** Can a resident of your country win the cash prize?

**Why it matters:** Splunk's prior Devpost hackathon (`splunkapptitude1.devpost.com`) restricted winners to residents of: the fifty U.S. states or D.C., Austria, Australia, Canada (excluding Quebec), France, Germany, Italy, Japan, Korea, the Netherlands, New Zealand, Singapore, Sweden, Switzerland, or the United Kingdom. **India was not on that list.** A third-party listing site calls this hackathon "global" but that is not authoritative.

**The current state of the rules page:** As of writing, the Splunk Agentic Ops Hackathon rules page reads *"The Official Rules for the Hackathon are not yet available. They will be posted prior to the start of the Hackathon."* The rules are not published.

**How to resolve, in order:**
1. Refresh `splunk.devpost.com/rules` daily until the official rules publish.
2. Post the question in the `#splunk-ai-hackathon` Slack channel.
3. Email the Devpost hackathon organizer contact directly.

**Outcomes and what each means:**
- **Your country is eligible.** Proceed normally. Cash prize is in play.
- **Your country is excluded.** You can still submit and win `.conf26` passes (often awarded regardless of cash eligibility), portfolio value, and recognition. Reframe the team's expectations now, not in week 3.

---

## Gate 2: Hosted-model access in your provisioned environment

**The question:** Can your Splunk Enterprise trial actually call Splunk-hosted Foundation-Sec and CDTSM as APIs?

**Why it matters:** The hackathon's getting-started path is a 60-day Splunk Enterprise free trial (on-premises install). Hosted Models have historically been a Splunk **Cloud** feature. There may be a mismatch — meaning your trial environment cannot reach the hosted-model endpoints. Several proposals circulating assume hosted access; if that assumption is wrong, those proposals break.

**Why this is not a blocker for Counterspell:** Both relevant models are open-weight on Hugging Face:
- `fdtn-ai/Foundation-Sec-1.1-8B-Instruct` (and the GGUF quantized variant)
- The Cisco Deep Time Series Model

The Counterspell architecture treats the model endpoint as a configurable seam. Whichever path is available, the rest of the system is unchanged:
- **Path A (Splunk-hosted available):** Point the agent runtime at the Splunk hosted-model endpoint.
- **Path B (Splunk-hosted unavailable):** Self-host Foundation-Sec via vLLM, Ollama, or LM Studio in a container alongside the agent runtime. Point the agent runtime at `http://localhost:<port>`.

Either path satisfies "the project uses Splunk hosted models" honestly in the write-up — Path A literally, Path B by using the open-weight artifacts Splunk hosts.

**How to resolve:**
1. Install Splunk Enterprise trial + AI Toolkit + MCP Server app.
2. Attempt a hosted-model call from the AI Toolkit UI or via SPL.
3. Ask in `#splunk-ai-hackathon`: *"Are Splunk hosted models reachable from a Splunk Enterprise trial install, or only Splunk Cloud?"*
4. If the answer is Path B, pull the Foundation-Sec GGUF and stand up Ollama in parallel with Splunk on the same machine.

---

## Other facts circulating that you should NOT rely on without checking the official rules

The two research documents earlier in this conversation made several confident claims that I could not verify from primary sources. Treat all of these as unconfirmed:

- **The judging rubric** ("equally weighted: technical implementation, design/UX, potential impact, quality/creativity of the idea"). Plausible — this is the Devpost default — but not published.
- **Specific bonus prizes** ("Best Use of MCP Server", "Best Use of Splunk Hosted Models", "Best Use of Splunk Developer Tools"). Plausible based on vendor-hackathon norms, but not published.
- **The participant count.** It varies across page loads (323, 388, and 1,403 have all been observed). Do not anchor strategy to a specific number.

When the rules publish, re-read this entire docs set against them and adjust.

---

## Day-0 checklist

- [ ] Eligibility confirmed (cash or non-cash path chosen)
- [ ] Hosted-model path chosen (Path A or Path B)
- [ ] Splunk Enterprise trial installed
- [ ] MCP Server, AI Assistant for SPL, AI Toolkit installed from Splunkbase
- [ ] HEC token created
- [ ] `counterspell` index created
- [ ] Joined `#splunk-ai-hackathon` Slack
- [ ] Read the rules page once it publishes; cross-check this docs set

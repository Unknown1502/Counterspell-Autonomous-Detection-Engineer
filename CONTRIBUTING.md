# Contributing to Counterspell

Thanks for considering a contribution. The project is small and the bar for
changes is whatever keeps the demo loop tight and the platform integration
honest.

## Ground rules

1. **The demo loop is sacred.** Anything that lengthens the threat-in →
   deployed-saved-search path needs a strong justification.
2. **No mocked actions.** Every `action` Counterspell takes against Splunk
   is a real SDK or MCP call. PRs that mock writes will be declined.
3. **Pydantic schemas are the contracts.** If you change a schema in
   [`schemas.py`](src/counterspell/schemas.py), update the
   matching prompt in [`prompts.py`](src/counterspell/prompts.py) and
   the doc in [`docs/04_AGENT_DESIGN.md`](docs/04_AGENT_DESIGN.md).
4. **The Validator stays deterministic.** No LLM may judge TP/FP — that
   keeps the FP curve trustworthy.

## Development setup

```powershell
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
# fill in tokens
python scripts/verify_environment.py
```

## Running tests

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD=1  # only needed if you have a broken global pytest plugin
python -m pytest tests/ -v
```

41 tests should pass in under 2 seconds. CI runs the same suite on
Python 3.10, 3.11, and 3.12.

## Pull request checklist

- [ ] Tests pass locally: `python -m pytest tests/`
- [ ] If you changed an agent, the matching test file is updated.
- [ ] If you touched [`prompts.py`](src/counterspell/prompts.py), you
      also updated [`docs/05_PROMPT_LIBRARY.md`](docs/05_PROMPT_LIBRARY.md).
- [ ] If you changed a Pydantic schema, you ran the orchestrator once
      end-to-end against a live Splunk to confirm the LLM still returns
      valid JSON.
- [ ] The PR description explains *why*; the code change explains *what*.

## What we won't accept

Per the explicit scope in [`docs/01_OVERVIEW.md`](docs/01_OVERVIEW.md):

- Live alert triage agents
- SOAR / response actions (firewall API, account lockouts, etc.)
- Slack / Jira / Confluence integrations
- A separate web UI (the Splunk dashboard is the surface)

These are reasonable products. They are not Counterspell.

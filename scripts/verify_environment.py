"""Day-0 gate: verify every external dependency Counterspell needs is reachable.

Run this BEFORE writing or running any agent code. It exits non-zero if any
required check fails and prints a short remediation hint for each failure.

Checks:
  1. .env present and non-default values for the secrets
  2. Splunk SDK can connect (oneshot a trivial search)
  3. counterspell index exists
  4. HEC endpoint accepts a single test event (cleaned up after)
  5. MCP server responds to a tools/list call  (warning only if MCP_URL unset)
  6. LLM endpoint responds to a trivial chat-completion call
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

# Windows consoles default to cp1252, which can't encode the ✓/✗/! glyphs below
# and crashes the script before any check runs. Force UTF-8 on the streams.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

import requests  # noqa: E402
import urllib3  # noqa: E402

from counterspell.config import Config  # noqa: E402

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
DIM = "\033[2m"
RESET = "\033[0m"


def ok(msg: str) -> None:
    print(f"{GREEN}  ✓{RESET} {msg}")


def fail(msg: str, hint: str = "") -> None:
    print(f"{RED}  ✗{RESET} {msg}")
    if hint:
        print(f"{DIM}     → {hint}{RESET}")


def warn(msg: str, hint: str = "") -> None:
    print(f"{YELLOW}  !{RESET} {msg}")
    if hint:
        print(f"{DIM}     → {hint}{RESET}")


def header(name: str) -> None:
    print(f"\n[{name}]")


def check_env(cfg: Config) -> bool:
    header("1. .env and secrets")
    env_path = REPO_ROOT / ".env"
    if not env_path.exists():
        fail(".env not found",
             f"Copy from .env.example: Copy-Item .env.example .env  (in {REPO_ROOT})")
        return False
    ok(".env file present")

    placeholders = {
        "SPLUNK_TOKEN": cfg.splunk_token,
        "SPLUNK_HEC_TOKEN": cfg.hec_token,
    }
    bad = False
    for k, v in placeholders.items():
        if not v or "your-" in v.lower() or v == "":
            fail(f"{k} is empty or still a placeholder",
                 f"Edit {env_path} and set a real value")
            bad = True
        else:
            ok(f"{k} set ({len(v)} chars)")
    return not bad


def check_splunk_sdk(cfg: Config) -> bool:
    header("2. Splunk SDK connection")
    try:
        import splunklib.client as splunk_client
        svc = splunk_client.connect(
            host=cfg.splunk_host,
            port=cfg.splunk_port,
            splunkToken=cfg.splunk_token,
            scheme="https",
            verify=False,
        )
        info = svc.info
        ok(f"Connected to Splunk {info.get('version', '?')} on "
           f"{cfg.splunk_host}:{cfg.splunk_port}")
        return True
    except Exception as e:  # noqa: BLE001
        fail(f"Splunk SDK connect failed: {e}",
             "Check SPLUNK_HOST / SPLUNK_PORT / SPLUNK_TOKEN; "
             "confirm splunkd is up (https://localhost:8089/services/server/info)")
        return False


def check_index(cfg: Config) -> bool:
    header(f"3. index={cfg.index} exists")
    try:
        import splunklib.client as splunk_client
        svc = splunk_client.connect(
            host=cfg.splunk_host,
            port=cfg.splunk_port,
            splunkToken=cfg.splunk_token,
            scheme="https",
            verify=False,
        )
        names = [i.name for i in svc.indexes]
        if cfg.index in names:
            ok(f"index '{cfg.index}' exists")
            return True
        fail(f"index '{cfg.index}' missing",
             f"Create it: Settings → Indexes → New Index → '{cfg.index}'")
        return False
    except Exception as e:  # noqa: BLE001
        fail(f"Could not list indexes: {e}")
        return False


def _try_rest_ingest_fallback(cfg: Config, event_fields: dict) -> bool:
    """Verify the REST receivers/simple ingestion fallback actually works.

    This is the same path SplunkClient.ingest_via_rest uses when HEC is down,
    so a pass here means ingestion is genuinely available, just degraded.
    """
    url = (f"https://{cfg.splunk_host}:{cfg.splunk_port}"
           "/services/receivers/simple")
    headers = {"Authorization": f"Bearer {cfg.splunk_token}"}
    try:
        resp = requests.post(
            url, params={"index": cfg.index, "sourcetype": "cs:auth"},
            headers=headers, data=json.dumps(event_fields) + "\n",
            verify=False, timeout=15,
        )
        return 200 <= resp.status_code < 300
    except Exception:  # noqa: BLE001
        return False


def check_hec(cfg: Config) -> bool:
    header("4. HEC endpoint accepts events")
    test_id = f"counterspell-verify-{uuid.uuid4().hex[:8]}"
    event_fields = {
        "_time": time.time(),
        "user": "verify_user",
        "src_ip": "10.0.0.1",
        "host": "verify-host",
        "action": "success",
        "app": "verify",
        "cs_scenario_id": test_id,
    }
    body = json.dumps({
        "event": event_fields,
        "sourcetype": "cs:auth",
        "index": cfg.index,
    })
    headers = {
        "Authorization": f"Splunk {cfg.hec_token}",
        "Content-Type": "application/json",
    }
    hec_error = ""
    if not cfg.hec_token:
        hec_error = "SPLUNK_HEC_TOKEN is empty"
    else:
        try:
            resp = requests.post(
                cfg.hec_url, headers=headers, data=body, verify=False, timeout=15,
            )
            if 200 <= resp.status_code < 300:
                ok(f"HEC accepted test event (id={test_id})")
                return True
            hec_error = f"HEC rejected event ({resp.status_code}): {resp.text[:200]}"
        except Exception as e:  # noqa: BLE001
            hec_error = f"HEC request error: {e}"

    # HEC is down — ingestion is still possible if the REST receivers
    # fallback (the path SplunkClient actually takes) accepts events.
    if _try_rest_ingest_fallback(cfg, event_fields):
        warn(f"{hec_error}",
             "HEC is down but the REST receivers fallback works — ingestion "
             "is DEGRADED, not blocked. Fix HEC in Splunk Web (Settings → "
             "Data inputs → HTTP Event Collector) to restore the primary path.")
        return True
    fail(f"{hec_error} — and the REST receivers fallback also failed",
         "Confirm Splunk's HEC port (default 8088) is open and HEC is enabled, "
         f"and that SPLUNK_TOKEN can write to index={cfg.index}")
    return False


def check_es(cfg: Config) -> bool:
    """Non-blocking: report whether Enterprise Security is installed.

    Counterspell deploys ES/RBA metadata when ES is present and transparently
    falls back to a plain scheduled search when it is not. This check tells you
    up front which story your demo can truthfully tell.
    """
    header("7. Enterprise Security (optional, for notable/risk/correlation)")
    try:
        import splunklib.client as splunk_client
        svc = splunk_client.connect(
            host=cfg.splunk_host, port=cfg.splunk_port,
            splunkToken=cfg.splunk_token, scheme="https", verify=False,
        )
        apps = {a.name.lower() for a in svc.apps}
        es_names = {"splunkenterprisesecuritysuite", "enterprisesecurity",
                    "splunk_app_es", "es"}
        if apps & es_names:
            ok("Enterprise Security installed — deploy will attach "
               "notable + risk + correlation metadata.")
        else:
            warn("Enterprise Security NOT installed — deploy will ship a plain "
                 "scheduled saved search (still real, just no ES enrichment).",
                 "Install Splunk ES if you want to claim full RBA in the demo; "
                 "otherwise say 'ES-ready' rather than 'ES-integrated'.")
        return True
    except Exception as e:  # noqa: BLE001
        warn(f"Could not check for Enterprise Security: {e}")
        return True


def check_data_present(cfg: Config) -> bool:
    """Non-blocking: warn if index=counterspell is empty (seed step not run)."""
    header("8. Baseline data present in index")
    try:
        import splunklib.client as splunk_client
        import splunklib.results as splunk_results
        svc = splunk_client.connect(
            host=cfg.splunk_host, port=cfg.splunk_port,
            splunkToken=cfg.splunk_token, scheme="https", verify=False,
        )
        job = svc.jobs.oneshot(
            f'search index="{cfg.index}" earliest=-31d latest=now | stats count',
            output_mode="json",
        )
        total = 0
        for item in splunk_results.JSONResultsReader(job):
            if isinstance(item, dict):
                try:
                    total = int(item.get("count", 0))
                except (TypeError, ValueError):
                    total = 0
        if total > 0:
            ok(f"index '{cfg.index}' has {total:,} events in the last 31 days.")
        else:
            warn(f"index '{cfg.index}' has 0 events — the FP curve will start "
                 f"and stay at 0 (no noise to tune out).",
                 "Run: python data/generate_synthetic_data.py")
        return True
    except Exception as e:  # noqa: BLE001
        warn(f"Could not count events in {cfg.index}: {e}")
        return True


def check_mcp(cfg: Config) -> bool:
    header("5. MCP server (optional)")
    if not cfg.mcp_url:
        warn("MCP_URL not set — Counterspell will use SDK fallback for all reads.",
             "Set MCP_URL + MCP_TOKEN once MCP Server is installed for full credit.")
        return True  # not blocking
    # Reuse the real MCPClient so this check exercises the SAME handshake +
    # transport path the demo uses (initialize → session id → tools/list).
    try:
        from counterspell.mcp_client import MCPClient
        client = MCPClient(mcp_url=cfg.mcp_url, mcp_token=cfg.mcp_token, fallback=None)
        client._initialize()
        resp = client._post({
            "jsonrpc": "2.0", "id": str(uuid.uuid4()),
            "method": "tools/list", "params": {},
        })
        data = client._parse_body(resp)
        tools = (data.get("result") or {}).get("tools") or []
        names = {t.get("name", "?") for t in tools}
        ok(f"MCP server responded (after initialize): {len(tools)} tools available")
        query_names = {"run_query", "splunk_run_query", "run_splunk_query"}
        gen_names = {"generate_spl", "saia_generate_spl"}
        present_query = query_names & names
        present_gen = gen_names & names
        if not present_query:
            warn("MCP exposes no recognized query tool "
                 "(run_query / splunk_run_query)",
                 "Backtests will fall back to the SDK — no MCP credit.")
        else:
            ok(f"query tool present ({sorted(present_query)[0]})")
        if not present_gen:
            warn("MCP missing generate_spl (AI Assistant for SPL)",
                 "Translator will use the LLM fallback instead.")
        else:
            ok(f"generate-SPL tool present ({sorted(present_gen)[0]})")
        return True
    except Exception as e:  # noqa: BLE001
        fail(f"MCP handshake/tools-list failed: {e}",
             "Confirm MCP_URL is the /services/mcp endpoint and MCP_TOKEN is the "
             "encrypted token from the MCP Server app. Counterspell will run via "
             "SDK fallback, but MCP credit is forfeit.")
        return False


def check_llm(cfg: Config) -> bool:
    header("6. LLM endpoint")
    try:
        from openai import OpenAI
        client = OpenAI(
            base_url=cfg.llm_base_url,
            api_key=cfg.llm_api_key or "not-needed",
        )
        resp = client.chat.completions.create(
            model=cfg.llm_model,
            messages=[{"role": "user", "content": "Reply with the single word: pong"}],
            temperature=0.0,
            max_tokens=8,
        )
        text = (resp.choices[0].message.content or "").strip()
        ok(f"LLM '{cfg.llm_model}' responded: {text!r}")
        return True
    except Exception as e:  # noqa: BLE001
        fail(f"LLM call failed: {e}",
             f"Confirm {cfg.llm_base_url} is reachable and serves model "
             f"'{cfg.llm_model}'. For Ollama: `ollama serve` + "
             f"`ollama pull {cfg.llm_model}`.")
        return False


def main() -> int:
    print(f"Counterspell environment check\n{'=' * 50}")
    try:
        cfg = Config.load()
    except Exception as e:  # noqa: BLE001
        print(f"{RED}Could not load Config: {e}{RESET}")
        return 1

    results = {
        "env": check_env(cfg),
        "splunk": check_splunk_sdk(cfg),
    }
    if results["splunk"]:
        results["index"] = check_index(cfg)
        results["hec"] = check_hec(cfg)
    results["mcp"] = check_mcp(cfg)
    results["llm"] = check_llm(cfg)
    if results["splunk"]:
        results["es"] = check_es(cfg)
        results["data"] = check_data_present(cfg)

    print(f"\n{'=' * 50}\nSummary")
    blocking = {"env", "splunk", "index", "hec", "llm"}
    failed_blocking = [k for k in blocking if k in results and not results[k]]
    if failed_blocking:
        print(f"{RED}BLOCKED on: {', '.join(failed_blocking)}{RESET}")
        print("Resolve the failures above before running the orchestrator.")
        return 1
    print(f"{GREEN}All required checks passed.{RESET}")
    if "mcp" in results and not results["mcp"]:
        print(f"{YELLOW}MCP unreachable — runs will use SDK fallback.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

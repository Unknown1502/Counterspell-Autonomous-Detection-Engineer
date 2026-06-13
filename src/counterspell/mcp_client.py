"""Splunk MCP Server JSON-RPC client with transparent SDK fallback."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import requests
import urllib3

from .splunk_client import SplunkClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


def _extract_rows(resp: dict[str, Any]) -> list[dict[str, Any]]:
    """Find all text content blocks in an MCP response and parse them as JSON rows."""
    result = resp.get("result", resp) or {}
    blocks = result.get("content") or []
    rows: list[dict[str, Any]] = []
    for blk in blocks:
        if isinstance(blk, dict) and blk.get("type") == "text":
            text = blk.get("text", "") or ""
            text = text.strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            rows.append(obj)
                    except json.JSONDecodeError:
                        continue
                continue
            if isinstance(parsed, list):
                rows.extend([r for r in parsed if isinstance(r, dict)])
            elif isinstance(parsed, dict):
                inner = (
                    parsed.get("results")
                    or parsed.get("rows")
                    or parsed.get("data")
                )
                if isinstance(inner, list):
                    rows.extend([r for r in inner if isinstance(r, dict)])
                else:
                    rows.append(parsed)
    return rows


def _extract_text(resp: dict[str, Any]) -> str:
    """Join all text content blocks in an MCP response with newlines."""
    result = resp.get("result", resp) or {}
    blocks = result.get("content") or []
    parts: list[str] = []
    for blk in blocks:
        if isinstance(blk, dict) and blk.get("type") == "text":
            parts.append(blk.get("text", "") or "")
    return "\n".join(parts).strip()


# Splunk MCP Server tool names vary by version. The installed v1.2.0 app
# registers tools under a `splunk_` prefix (verified via tools/list:
# `splunk_run_query`, `splunk_generate_spl`); its builtin_tools.json lists the
# bare names, and the web docs reference other variants. We try the v1.2.0
# prefixed names FIRST, then bare/legacy variants, so one client works across
# versions without a wasted 404 on the common case. The tool that actually
# worked is remembered after the first success.
QUERY_TOOL_NAMES = ("splunk_run_query", "run_query", "run_splunk_query")
GENERATE_SPL_TOOL_NAMES = ("splunk_generate_spl", "generate_spl", "saia_generate_spl")
GENERATE_SPL_TOOL = GENERATE_SPL_TOOL_NAMES[0]  # back-compat alias

# MCP protocol version the client advertises in the initialize handshake.
MCP_PROTOCOL_VERSION = "2025-06-18"


class MCPClient:
    """Calls Splunk MCP Server tools over JSON-RPC (streamable HTTP), with SDK fallback.

    The official server speaks JSON-RPC 2.0 over streamable HTTP at
    `/services/mcp` (mgmt port 8089), authenticates with an encrypted Bearer
    token, and requires an `initialize` handshake before `tools/call`. This
    client performs that handshake once, carries the returned `Mcp-Session-Id`,
    and tries the current query-tool name with a legacy fallback.

    Crucially, MCP usage is *observable*: `last_source` records whether the most
    recent read was served by "mcp" or the "sdk" fallback, and `used_mcp` stays
    True only if MCP genuinely served at least one call. This stops you from
    silently losing MCP credit (e.g. a wrong tool name) while believing you had
    it.
    """

    def __init__(self, mcp_url: str, mcp_token: str, fallback: SplunkClient) -> None:
        self.mcp_url = mcp_url
        self.mcp_token = mcp_token
        self.fallback = fallback
        self._session_id: str | None = None
        self._initialized = False
        self._query_tool: str | None = None  # resolved after first success
        self._generate_tool: str | None = None  # resolved after first success
        self.used_mcp = False            # True once MCP serves any real call
        self.last_source: str | None = None  # "mcp" | "sdk" per read

    def _enabled(self) -> bool:
        return bool(self.mcp_url)

    def _headers(self) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {self.mcp_token}",
            "Content-Type": "application/json",
            # Streamable HTTP servers commonly require the client to accept
            # both JSON and SSE responses.
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        return h

    @staticmethod
    def _parse_body(resp: "requests.Response") -> dict[str, Any]:
        """Parse a JSON or SSE (text/event-stream) MCP response body into a dict."""
        ctype = resp.headers.get("Content-Type", "")
        if "text/event-stream" in ctype:
            # SSE frames: lines like `data: {...}`. Take the last data payload.
            payload = ""
            for line in resp.text.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    payload = line[len("data:"):].strip()
            return json.loads(payload) if payload else {}
        return resp.json()

    def _post(self, body: dict[str, Any]) -> "requests.Response":
        resp = requests.post(
            self.mcp_url,
            headers=self._headers(),
            data=json.dumps(body),
            verify=False,
            timeout=70,
        )
        if not (200 <= resp.status_code < 300):
            raise RuntimeError(
                f"MCP {body.get('method')} failed ({resp.status_code}): "
                f"{resp.text[:300]}"
            )
        # Capture the session id the server hands back on initialize.
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self._session_id = sid
        return resp

    def _initialize(self) -> None:
        """Perform the MCP initialize handshake once per client."""
        if self._initialized:
            return
        body = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "counterspell", "version": "0.1.0"},
            },
        }
        self._post(body)
        # Per spec, follow initialize with an initialized notification.
        try:
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except Exception:  # noqa: BLE001 — some servers don't require this.
            pass
        self._initialized = True

    def _call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call one MCP tool, ensuring the initialize handshake has run."""
        self._initialize()
        body = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
        resp = self._post(body)
        data = self._parse_body(resp)
        # A JSON-RPC error (e.g. unknown tool) comes back 200 with an "error".
        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(f"MCP tool {tool} error: {data['error']}")
        return data

    def run_query(
        self, spl: str, earliest: str = "-30d", latest: str = "now"
    ) -> list[dict[str, Any]]:
        """Run an SPL search via MCP, falling back to direct SDK oneshot on any error."""
        if not self._enabled():
            self.last_source = "sdk"
            return self.fallback.oneshot(spl, earliest=earliest, latest=latest)

        # Resolve the query tool name once: current first, then legacy.
        candidates = (
            (self._query_tool,) if self._query_tool else QUERY_TOOL_NAMES
        )
        last_err: Exception | None = None
        for tool in candidates:
            try:
                resp = self._call(
                    tool,
                    {
                        "query": spl,
                        "earliest_time": earliest,
                        "latest_time": latest,
                    },
                )
                self._query_tool = tool  # remember what worked
                self.used_mcp = True
                self.last_source = "mcp"
                return _extract_rows(resp)
            except Exception as e:  # noqa: BLE001
                last_err = e
                log.warning("MCP query tool %r failed: %s", tool, e)
        log.warning("All MCP query tools failed, falling back to SDK: %s", last_err)
        self.last_source = "sdk"
        return self.fallback.oneshot(spl, earliest=earliest, latest=latest)

    def generate_spl(self, intent: str) -> str | None:
        """Ask the Splunk AI Assistant for SPL via MCP; return None on failure or if disabled."""
        if not self._enabled():
            return None
        candidates = (
            (self._generate_tool,) if self._generate_tool else GENERATE_SPL_TOOL_NAMES
        )
        for tool in candidates:
            try:
                resp = self._call(tool, {"question": intent})
                text = _extract_text(resp)
                if text:
                    self._generate_tool = tool  # remember what worked
                    self.used_mcp = True
                    return text
            except Exception as e:  # noqa: BLE001
                log.warning("MCP generate-SPL tool %r failed: %s", tool, e)
        return None

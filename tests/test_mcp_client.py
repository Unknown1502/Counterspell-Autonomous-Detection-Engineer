"""MCP response parsing + SDK fallback contract."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from counterspell.mcp_client import MCPClient, _extract_rows, _extract_text


def _content(text: str) -> dict[str, Any]:
    return {"result": {"content": [{"type": "text", "text": text}]}}


def test_extract_rows_from_json_array():
    rows = _extract_rows(_content('[{"a": 1}, {"b": 2}]'))
    assert rows == [{"a": 1}, {"b": 2}]


def test_extract_rows_from_results_envelope():
    rows = _extract_rows(_content('{"results": [{"a": 1}]}'))
    assert rows == [{"a": 1}]


def test_extract_rows_from_ndjson_lines():
    blob = '{"a": 1}\n{"b": 2}\n'
    rows = _extract_rows(_content(blob))
    assert rows == [{"a": 1}, {"b": 2}]


def test_extract_text_joins_content_blocks():
    resp = {"result": {"content": [
        {"type": "text", "text": "first"},
        {"type": "text", "text": "second"},
    ]}}
    assert _extract_text(resp) == "first\nsecond"


def test_run_query_falls_back_to_sdk_when_mcp_disabled():
    """When MCP_URL is empty, every read goes straight to the SDK fallback."""
    fallback = MagicMock()
    fallback.oneshot.return_value = [{"row": 1}]
    mcp = MCPClient(mcp_url="", mcp_token="", fallback=fallback)
    result = mcp.run_query("search ...", earliest="-1d", latest="now")
    assert result == [{"row": 1}]
    fallback.oneshot.assert_called_once_with("search ...", earliest="-1d", latest="now")


def test_run_query_falls_back_to_sdk_when_mcp_raises():
    fallback = MagicMock()
    fallback.oneshot.return_value = [{"row": 2}]
    mcp = MCPClient(mcp_url="https://mcp.local", mcp_token="t", fallback=fallback)
    mcp._call = MagicMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
    result = mcp.run_query("spl")
    assert result == [{"row": 2}]
    fallback.oneshot.assert_called_once()
    assert mcp.last_source == "sdk"
    assert mcp.used_mcp is False


def test_run_query_uses_installed_tool_name_and_marks_used_mcp():
    """The installed v1.2 server registers the tool as `splunk_run_query` — tried first."""
    fallback = MagicMock()
    mcp = MCPClient(mcp_url="https://mcp.local", mcp_token="t", fallback=fallback)
    calls: list[str] = []

    def fake_call(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        calls.append(tool)
        return {"result": {"content": [{"type": "text", "text": '[{"count": 5}]'}]}}

    mcp._call = fake_call  # type: ignore[method-assign]
    rows = mcp.run_query("search ...")
    assert rows == [{"count": 5}]
    assert calls[0] == "splunk_run_query"  # v1.2.0 registered name tried first
    assert mcp.used_mcp is True
    assert mcp.last_source == "mcp"
    fallback.oneshot.assert_not_called()


def test_run_query_falls_back_to_prefixed_tool_name():
    """If the first tool name is unknown, try the remaining variants in order."""
    fallback = MagicMock()
    mcp = MCPClient(mcp_url="https://mcp.local", mcp_token="t", fallback=fallback)
    calls: list[str] = []

    def fake_call(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        calls.append(tool)
        if tool in ("splunk_run_query", "run_query"):
            raise RuntimeError("unknown tool")
        return {"result": {"content": [{"type": "text", "text": '[{"count": 1}]'}]}}

    mcp._call = fake_call  # type: ignore[method-assign]
    rows = mcp.run_query("spl")
    assert rows == [{"count": 1}]
    assert calls == ["splunk_run_query", "run_query", "run_splunk_query"]
    assert mcp._query_tool == "run_splunk_query"  # remembered for next time
    assert mcp.used_mcp is True


def test_generate_spl_returns_none_when_disabled():
    fallback = MagicMock()
    mcp = MCPClient(mcp_url="", mcp_token="", fallback=fallback)
    assert mcp.generate_spl("brute force") is None


def test_generate_spl_uses_correct_tool_and_marks_used_mcp():
    fallback = MagicMock()
    mcp = MCPClient(mcp_url="https://mcp.local", mcp_token="t", fallback=fallback)
    captured: dict[str, Any] = {}

    def fake_call(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        captured["tool"] = tool
        return {"result": {"content": [{"type": "text",
                "text": 'search index="counterspell" ...'}]}}

    mcp._call = fake_call  # type: ignore[method-assign]
    spl = mcp.generate_spl("detect brute force")
    assert spl and spl.startswith("search")
    assert captured["tool"] == "splunk_generate_spl"  # v1.2.0 registered name tried first
    assert mcp.used_mcp is True

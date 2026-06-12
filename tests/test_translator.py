"""Translator normalization + MCP/LLM routing."""

from __future__ import annotations

from unittest.mock import MagicMock

from counterspell.agents.translator import Translator, _normalize
from counterspell.schemas import DetectionDesign, SplOutput


def _design() -> DetectionDesign:
    return DetectionDesign(
        title="Demo",
        mitre_techniques=["T1110"],
        rationale="r",
        sourcetypes=["cs:auth"],
        key_fields=["user", "src_ip"],
        logic="many failed logins",
        thresholds={"window_min": 10, "failures": 15},
        false_positive_notes="",
    )


def test_normalize_passes_pipe_through():
    assert _normalize('| tstats count where index="counterspell" ...').startswith("|")


def test_normalize_passes_search_through():
    assert _normalize('search index="counterspell" ...').lower().startswith("search")


def test_normalize_prefixes_bare_predicate_with_search():
    out = _normalize('index="counterspell" action=failure')
    assert out.lower().startswith("search index=")


def test_to_spl_prefers_mcp_when_it_returns_valid_spl():
    mcp = MagicMock()
    mcp.generate_spl.return_value = 'search index="counterspell" sourcetype=cs:auth action=failure | stats count by user'
    llm = MagicMock()
    t = Translator(llm, mcp)
    spl = t.to_spl(_design())
    assert spl.startswith("search index=")
    llm.complete_json.assert_not_called()


def test_to_spl_falls_back_to_llm_when_mcp_returns_none():
    mcp = MagicMock()
    mcp.generate_spl.return_value = None
    llm = MagicMock()
    llm.complete_json.return_value = SplOutput(
        spl='search index="counterspell" sourcetype=cs:auth action=failure | stats count by user'
    )
    t = Translator(llm, mcp)
    spl = t.to_spl(_design())
    assert "index=" in spl
    llm.complete_json.assert_called_once()


def test_to_spl_falls_back_to_llm_when_mcp_returns_obviously_wrong_text():
    mcp = MagicMock()
    mcp.generate_spl.return_value = "Sorry, I could not generate SPL for this."
    llm = MagicMock()
    llm.complete_json.return_value = SplOutput(
        spl='search index="counterspell" sourcetype=cs:auth | head 1'
    )
    t = Translator(llm, mcp)
    spl = t.to_spl(_design())
    assert "index=" in spl
    llm.complete_json.assert_called_once()

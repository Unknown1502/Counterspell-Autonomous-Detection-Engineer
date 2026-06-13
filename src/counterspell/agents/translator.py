"""Translator agent: converts a detection design into valid SPL via MCP or LLM fallback."""

from __future__ import annotations

import re

from .. import prompts
from ..llm_client import LLMClient
from ..mcp_client import MCPClient
from ..schemas import DetectionDesign, SplOutput

# Inline time terms in the LLM's SPL (e.g. `earliest=-12h`) override the
# dispatch time range Splunk is given. The Validator deliberately backtests over
# a fixed `-31d..now` window so the rule meets the full 30-day baseline; if the
# model narrows that to a few hours, the historical noise floor vanishes and the
# FP curve is pinned at 0. We strip these terms so the backtest window governs.
_TIME_TERM = re.compile(
    r'\b(?:earliest|latest|earliest_time|latest_time|_index_earliest|_index_latest)'
    r'\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)',
    re.IGNORECASE,
)


def _strip_time_modifiers(spl: str) -> str:
    """Remove inline earliest/latest terms so the dispatch time range wins."""
    cleaned = _TIME_TERM.sub("", spl)
    # Collapse the whitespace / dangling pipes the removal can leave behind.
    cleaned = re.sub(r"\s{2,}", " ", cleaned)
    cleaned = re.sub(r"\|\s*\|", "|", cleaned)
    return cleaned.strip()


def _normalize(spl: str) -> str:
    """Strip inline time terms, then ensure SPL begins with `search` or a pipe."""
    s = _strip_time_modifiers((spl or "").strip())
    if not s:
        return s
    head = s.lstrip().lower()
    if head.startswith("search") or head.startswith("|"):
        return s
    return f"search {s}"


class Translator:
    """Generates SPL from a DetectionDesign, preferring the Splunk AI Assistant when available."""

    def __init__(self, llm: LLMClient, mcp: MCPClient) -> None:
        self.llm = llm
        self.mcp = mcp

    def to_spl(self, design: DetectionDesign) -> str:
        """Return a normalized SPL string for the given design."""
        intent = (
            f"{design.logic} Use index=counterspell, sourcetypes {design.sourcetypes}, "
            f"fields {design.key_fields}. Aggregate with stats; each row = one hit "
            "with entity + _time."
        )
        spl = self.mcp.generate_spl(intent)
        if spl and ("index=" in spl or spl.strip().lower().startswith("search")):
            return _normalize(spl)

        prompt = prompts.TRANSLATOR_FALLBACK.format(
            shared=prompts.SHARED_CONTEXT,
            design_json=design.model_dump_json(indent=2),
        )
        result = self.llm.complete_json(prompt, SplOutput, temperature=0.1)
        return _normalize(result.spl)

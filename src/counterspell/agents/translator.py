"""Translator agent: converts a detection design into valid SPL via MCP or LLM fallback."""

from __future__ import annotations

from .. import prompts
from ..llm_client import LLMClient
from ..mcp_client import MCPClient
from ..schemas import DetectionDesign, SplOutput


def _normalize(spl: str) -> str:
    """Ensure SPL begins with `search` or a pipe."""
    s = (spl or "").strip()
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

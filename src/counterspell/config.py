"""Configuration loader that merges config.yaml with environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv


@dataclass
class Config:
    """Aggregated runtime configuration for Counterspell."""

    splunk_host: str
    splunk_port: int
    splunk_token: str
    hec_url: str
    hec_token: str
    index: str
    mcp_url: str
    mcp_token: str
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    fp_threshold: int
    max_iters: int
    allow_best_effort: bool = False

    @classmethod
    def load(cls) -> "Config":
        repo_root = Path(__file__).resolve().parents[2]
        yaml_path = repo_root / "config.yaml"
        env_path = repo_root / ".env"
        if env_path.exists():
            load_dotenv(env_path)
        else:
            load_dotenv()

        with open(yaml_path, "r", encoding="utf-8") as f:
            ydata = yaml.safe_load(f) or {}

        return cls(
            splunk_host=os.environ.get("SPLUNK_HOST", "localhost"),
            splunk_port=int(os.environ.get("SPLUNK_PORT", "8089")),
            splunk_token=os.environ.get("SPLUNK_TOKEN", ""),
            hec_url=os.environ.get(
                "SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event"
            ),
            hec_token=os.environ.get("SPLUNK_HEC_TOKEN", ""),
            index=ydata.get("index", "counterspell"),
            mcp_url=os.environ.get("MCP_URL", ""),
            mcp_token=os.environ.get("MCP_TOKEN", ""),
            llm_base_url=os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1"),
            llm_api_key=os.environ.get("LLM_API_KEY", "not-needed-for-local"),
            llm_model=os.environ.get(
                "LLM_MODEL", ydata.get("llm_model", "foundation-sec-8b-instruct")
            ),
            fp_threshold=int(ydata.get("fp_threshold", 0)),
            max_iters=int(ydata.get("max_iters", 4)),
            allow_best_effort=bool(ydata.get("allow_best_effort", False)),
        )

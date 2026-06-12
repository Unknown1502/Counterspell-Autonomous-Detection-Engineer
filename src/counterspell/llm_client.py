"""OpenAI-compatible LLM client with JSON validation and one-shot repair retry."""

from __future__ import annotations

import json
import logging
import re
from typing import Type, TypeVar

from openai import OpenAI
from pydantic import BaseModel, ValidationError

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


def _strip_fences(text: str) -> str:
    """Remove ```json fences and return the outermost JSON object substring."""
    if not text:
        return text
    cleaned = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return cleaned[start : end + 1]
    return cleaned


class LLMClient:
    """OpenAI-compatible chat client that parses and validates JSON responses."""

    def __init__(self, base_url: str, api_key: str, model: str) -> None:
        self.client = OpenAI(base_url=base_url, api_key=api_key or "not-needed")
        self.model = model

    def complete_json(
        self,
        prompt: str,
        schema: Type[T],
        temperature: float = 0.2,
        max_retries: int = 1,
    ) -> T:
        """Send a single user prompt and return a validated instance of schema."""
        messages: list[dict[str, str]] = [{"role": "user", "content": prompt}]
        last_err: Exception | None = None
        attempts = max_retries + 1
        raw = ""
        for attempt in range(attempts):
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
            )
            raw = resp.choices[0].message.content or ""
            payload = _strip_fences(raw)
            try:
                return schema.model_validate_json(payload)
            except (ValidationError, json.JSONDecodeError) as e:
                last_err = e
                log.warning(
                    "LLM JSON validation failed (attempt %d/%d): %s",
                    attempt + 1,
                    attempts,
                    e,
                )
                messages.append({"role": "assistant", "content": raw})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your previous response did not validate against the required "
                            f"schema {schema.__name__}. Error:\n{e}\n\n"
                            "Return ONLY a valid JSON object matching the schema. "
                            "No markdown fences, no commentary."
                        ),
                    }
                )
        raise RuntimeError(
            f"LLM did not return valid {schema.__name__}: {last_err}"
        )

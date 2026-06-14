"""OpenAI-compatible LLM client with JSON validation and one-shot repair retry."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Type, TypeVar

from openai import OpenAI, RateLimitError
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
        # max_retries lets the SDK honor 429 `retry-after` headers with backoff;
        # we add our own rate-limit loop on top for free-tier TPM throttling.
        self.client = OpenAI(
            base_url=base_url,
            api_key=api_key or "not-needed",
            max_retries=4,
            timeout=90.0,
        )
        self.model = model

    def _create(self, **kwargs):
        """chat.completions.create with backoff on free-tier rate limits.

        Hosted free tiers (e.g. Groq's 8k tokens/minute) throttle bursts of the
        large schema-bearing prompts this loop sends. On a 429 we wait out the
        window (honoring the server's hint when present) and retry, so a run
        completes instead of dying mid-loop.
        """
        delays = [8, 16, 24, 32]
        for i, delay in enumerate(delays + [None]):
            try:
                return self.client.chat.completions.create(**kwargs)
            except RateLimitError as e:
                if delay is None:
                    raise
                wait = delay
                try:  # prefer the server's retry-after hint if available
                    ra = getattr(e, "response", None)
                    hdr = ra.headers.get("retry-after") if ra is not None else None
                    if hdr:
                        wait = max(wait, int(float(hdr)) + 1)
                except Exception:  # noqa: BLE001
                    pass
                log.warning("rate limited (attempt %d); waiting %ss", i + 1, wait)
                time.sleep(wait)

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
            resp = self._create(
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

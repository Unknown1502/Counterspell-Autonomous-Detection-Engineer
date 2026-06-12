"""LLM JSON parsing + repair-retry. Every agent depends on this working."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from counterspell.llm_client import LLMClient, _strip_fences


class Demo(BaseModel):
    name: str
    score: int


def _make_client(*responses: str) -> tuple[LLMClient, MagicMock]:
    """Build an LLMClient whose chat.completions.create returns the given strings."""
    client = LLMClient(base_url="http://x", api_key="k", model="m")
    mock = MagicMock()
    queue = list(responses)

    def _create(**_: Any) -> Any:
        text = queue.pop(0)
        resp = MagicMock()
        resp.choices = [MagicMock()]
        resp.choices[0].message.content = text
        return resp

    mock.chat.completions.create = MagicMock(side_effect=_create)
    client.client = mock
    return client, mock


def test_strip_fences_handles_plain_json():
    assert _strip_fences('{"a": 1}') == '{"a": 1}'


def test_strip_fences_strips_markdown_code_block():
    raw = '```json\n{"name": "x", "score": 7}\n```'
    assert _strip_fences(raw) == '{"name": "x", "score": 7}'


def test_strip_fences_extracts_object_from_chatty_response():
    raw = 'Sure! Here is the JSON:\n{"name": "x", "score": 7}\nLet me know if...'
    assert _strip_fences(raw) == '{"name": "x", "score": 7}'


def test_complete_json_first_try_success():
    client, mock = _make_client('{"name": "ok", "score": 5}')
    result = client.complete_json("prompt", Demo)
    assert isinstance(result, Demo)
    assert result.name == "ok" and result.score == 5
    assert mock.chat.completions.create.call_count == 1


def test_complete_json_repair_retry_on_invalid_json():
    bad = "this is not json at all"
    good = '{"name": "fixed", "score": 1}'
    client, mock = _make_client(bad, good)
    result = client.complete_json("prompt", Demo, max_retries=1)
    assert result.name == "fixed"
    assert mock.chat.completions.create.call_count == 2

    msgs_second_call = mock.chat.completions.create.call_args_list[1].kwargs["messages"]
    repair_msg = msgs_second_call[-1]["content"]
    assert "did not validate" in repair_msg
    assert "Demo" in repair_msg


def test_complete_json_repair_retry_on_schema_mismatch():
    wrong_shape = '{"name": "x"}'   # missing required `score`
    correct = '{"name": "x", "score": 99}'
    client, _ = _make_client(wrong_shape, correct)
    result = client.complete_json("prompt", Demo, max_retries=1)
    assert result.score == 99


def test_complete_json_gives_up_after_retries():
    client, _ = _make_client("garbage", "still garbage")
    with pytest.raises(RuntimeError, match="did not return valid Demo"):
        client.complete_json("prompt", Demo, max_retries=1)


def test_complete_json_handles_fenced_response_without_retry():
    fenced = '```json\n{"name": "fenced", "score": 3}\n```'
    client, mock = _make_client(fenced)
    result = client.complete_json("prompt", Demo)
    assert result.name == "fenced"
    assert mock.chat.completions.create.call_count == 1

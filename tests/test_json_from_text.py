"""Tests for defensive JSON extraction from LLM output."""

from src.llm.client import _json_from_text


def test_plain_json_object():
    assert _json_from_text('{"key": "val"}') == {"key": "val"}


def test_plain_json_array():
    assert _json_from_text('[1, 2, 3]') == [1, 2, 3]


def test_markdown_code_fence_json():
    text = 'Sure! Here is the result:\n```json\n{"a": 1}\n```\nHope that helps!'
    assert _json_from_text(text) == {"a": 1}


def test_markdown_code_fence_no_language():
    text = '```\n[{"sha256": "abc", "accepted": true}]\n```'
    assert _json_from_text(text) == [{"sha256": "abc", "accepted": True}]


def test_conversational_filler():
    text = 'Here is the JSON output:\n{"sha256": "abc123", "accepted": true}'
    result = _json_from_text(text)
    assert result == {"sha256": "abc123", "accepted": True}


def test_trailing_commas():
    text = '{"a": 1, "b": 2,}'
    assert _json_from_text(text) == {"a": 1, "b": 2}


def test_trailing_comma_in_array():
    text = '[1, 2, 3,]'
    assert _json_from_text(text) == [1, 2, 3]


def test_python_booleans():
    text = '[{"accepted": True, "sha256": "abc"}]'
    result = _json_from_text(text)
    assert result == [{"accepted": True, "sha256": "abc"}]


def test_python_none():
    text = '{"key": None}'
    assert _json_from_text(text) == {"key": None}


def test_nested_json_extraction():
    text = "The analysis shows:\n[{\"x\": 1}]\nEnd of report."
    assert _json_from_text(text) == [{"x": 1}]


def test_empty_input_returns_none():
    assert _json_from_text("") is None
    assert _json_from_text("   ") is None


def test_no_json_returns_none():
    assert _json_from_text("no json here at all") is None


def test_malformed_beyond_repair_returns_none():
    assert _json_from_text("{{{invalid json content") is None


def test_combined_quirks_in_fence():
    text = '```json\n[{"accepted": True, "reason": "malware",}]\n```'
    result = _json_from_text(text)
    assert result == [{"accepted": True, "reason": "malware"}]

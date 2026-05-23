"""LLM client coercion, JSON parsing, and semantic hash filter."""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.llm.client import (
    _coerce_source_decision,
    _json_from_text,
    semantic_filter_hashes,
)

SHA = "a" * 64
ITEMS = [{"sha256": SHA, "url": "https://example.com", "context": "malware trojan PE loader"}]


def test_coerce_source_decision_infers_registry_fields():
    decision = _coerce_source_decision(
        {"source_type": "malwarebazaar"},
        ["malwarebazaar", "sysinternals"],
        {"malwarebazaar": 1, "sysinternals": 0},
    )
    assert decision is not None
    assert decision.expected_label == 1


def test_coerce_source_decision_filters_mixed_label_sources():
    decision = _coerce_source_decision(
        {"source_type": "malwarebazaar", "selected_sources": ["malwarebazaar", "sysinternals"]},
        ["malwarebazaar", "sysinternals"],
        {"malwarebazaar": 1, "sysinternals": 0},
    )
    assert decision.selected_sources == ["malwarebazaar"]


@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"key": "val"}', {"key": "val"}),
        ('```json\n{"a": 1}\n```', {"a": 1}),
        ('Here is the JSON:\n{"sha256": "abc", "accepted": true}', {"sha256": "abc", "accepted": True}),
        ('{"a": 1, "b": 2,}', {"a": 1, "b": 2}),
    ],
)
def test_json_from_text(text, expected):
    assert _json_from_text(text) == expected


def test_json_from_text_empty_or_invalid():
    assert _json_from_text(None) is None
    assert _json_from_text("no json here") is None


def test_semantic_filter_structured_output(monkeypatch):
    llm_output = json.dumps(
        [{"sha256": SHA, "accepted": True, "malware_family": "Emotet", "reason": "trojan"}]
    )
    model = MagicMock()
    model.invoke.return_value = MagicMock(content=llm_output)
    monkeypatch.setattr("src.llm.client._chat_model", lambda: model)
    result = semantic_filter_hashes(ITEMS)
    assert result[0]["malware_family"] == "Emotet"


def test_semantic_filter_fallback(monkeypatch):
    monkeypatch.setattr("src.llm.client._chat_model", lambda: None)
    result = semantic_filter_hashes(ITEMS)
    assert result[0]["semantic_reason"] == "keyword match fallback"


def test_semantic_filter_rejects_hash(monkeypatch):
    llm_output = json.dumps([{"sha256": SHA, "accepted": False, "reason": "benign"}])
    model = MagicMock()
    model.invoke.return_value = MagicMock(content=llm_output)
    monkeypatch.setattr("src.llm.client._chat_model", lambda: model)
    assert semantic_filter_hashes(ITEMS) == []

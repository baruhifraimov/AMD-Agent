"""Tests for structured LLM output from semantic_filter_hashes."""

import json
from unittest.mock import MagicMock, patch

from src.llm.client import SemanticHashVerdict, semantic_filter_hashes


def _mock_model_response(content: str):
    response = MagicMock()
    response.content = content
    return response


SHA = "a" * 64
ITEMS = [{"sha256": SHA, "url": "https://example.com", "context": "malware trojan PE loader"}]


def test_structured_output_includes_all_fields(monkeypatch):
    llm_output = json.dumps([
        {
            "sha256": SHA,
            "accepted": True,
            "malware_family": "Emotet",
            "is_technical_report": True,
            "confidence_score": 0.9,
            "reason": "known trojan loader",
        }
    ])
    model = MagicMock()
    model.invoke.return_value = _mock_model_response(llm_output)
    monkeypatch.setattr("src.llm.client._chat_model", lambda: model)

    result = semantic_filter_hashes(ITEMS)

    assert len(result) == 1
    assert result[0]["malware_family"] == "Emotet"
    assert result[0]["is_technical_report"] is True
    assert result[0]["confidence_score"] == 0.9
    assert result[0]["semantic_reason"] == "known trojan loader"


def test_fallback_adds_default_structured_fields(monkeypatch):
    monkeypatch.setattr("src.llm.client._chat_model", lambda: None)

    result = semantic_filter_hashes(ITEMS)

    assert len(result) == 1
    assert result[0]["malware_family"] == ""
    assert result[0]["is_technical_report"] is False
    assert result[0]["confidence_score"] == 0.5
    assert result[0]["semantic_reason"] == "keyword match fallback"


def test_partial_llm_response_graceful_degradation(monkeypatch):
    llm_output = json.dumps([{"sha256": SHA, "accepted": True, "reason": "malware"}])
    model = MagicMock()
    model.invoke.return_value = _mock_model_response(llm_output)
    monkeypatch.setattr("src.llm.client._chat_model", lambda: model)

    result = semantic_filter_hashes(ITEMS)

    assert len(result) == 1
    assert result[0]["malware_family"] == ""
    assert result[0]["confidence_score"] == 0.5
    assert result[0]["is_technical_report"] is False


def test_rejected_hash_not_returned(monkeypatch):
    llm_output = json.dumps([
        {"sha256": SHA, "accepted": False, "confidence_score": 0.1, "reason": "benign"}
    ])
    model = MagicMock()
    model.invoke.return_value = _mock_model_response(llm_output)
    monkeypatch.setattr("src.llm.client._chat_model", lambda: model)

    result = semantic_filter_hashes(ITEMS)

    assert result == []


def test_empty_items_returns_empty():
    assert semantic_filter_hashes([]) == []


def test_semantic_hash_verdict_model():
    v = SemanticHashVerdict(sha256="abc", accepted=True, confidence_score=0.8)
    assert v.malware_family == ""
    assert v.is_technical_report is False
    assert v.confidence_score == 0.8


def test_fallback_rejects_non_malware_context(monkeypatch):
    monkeypatch.setattr("src.llm.client._chat_model", lambda: None)
    items = [{"sha256": SHA, "url": "", "context": "benign document pdf image"}]

    result = semantic_filter_hashes(items)

    assert result == []

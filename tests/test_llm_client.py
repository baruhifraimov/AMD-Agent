"""Tests for local LLM decision coercion and CTI query normalization."""

from src.llm.client import _coerce_source_decision, _normalize_cti_queries, generate_cti_queries


def test_coerce_source_decision_infers_registry_fields():
    decision = _coerce_source_decision(
        {"source_type": "malwarebazaar"},
        ["malwarebazaar", "sysinternals"],
        {"malwarebazaar": 1, "sysinternals": 0},
    )

    assert decision is not None
    assert decision.source_type == "malwarebazaar"
    assert decision.selected_sources == ["malwarebazaar"]
    assert decision.expected_label == 1


def test_coerce_source_decision_filters_mixed_label_sources():
    decision = _coerce_source_decision(
        {
            "source_type": "malwarebazaar",
            "selected_sources": ["malwarebazaar", "sysinternals"],
        },
        ["malwarebazaar", "sysinternals"],
        {"malwarebazaar": 1, "sysinternals": 0},
    )

    assert decision is not None
    assert decision.selected_sources == ["malwarebazaar"]
    assert decision.expected_label == 1


def test_normalize_cti_queries_from_dict_items():
    out = _normalize_cti_queries([{"query": "malware sha256 pe hashes"}])
    assert out == ["malware sha256 pe hashes"]


def test_normalize_cti_queries_from_q_key():
    out = _normalize_cti_queries([{"q": "recent campaign iocs"}])
    assert out == ["recent campaign iocs"]


def test_normalize_cti_queries_plain_strings():
    out = _normalize_cti_queries(["  plain query  ", "second"])
    assert out == ["plain query", "second"]


def test_normalize_cti_queries_rejects_dict_repr_strings():
    out = _normalize_cti_queries(["{'query': 'broken'}"])
    assert out == []


def test_generate_cti_queries_without_model_uses_defaults(monkeypatch):
    monkeypatch.setattr("src.llm.client._chat_model", lambda: None)
    defaults = ["default one", "default two"]
    assert generate_cti_queries(defaults, limit=2) == defaults

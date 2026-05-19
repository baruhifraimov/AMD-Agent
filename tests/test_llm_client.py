"""Tests for local LLM decision coercion."""

from src.llm.client import _coerce_source_decision


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

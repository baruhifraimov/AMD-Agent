"""Tests for MalShareProvider."""

from unittest.mock import MagicMock, patch

from src.sources.malshare import MalShareProvider


def test_discover_disabled_returns_empty(monkeypatch):
    monkeypatch.setattr("src.config.MALSHARE_ENABLED", False)
    provider = MalShareProvider()
    assert provider.discover(5) == []


def test_discover_returns_candidates(monkeypatch):
    monkeypatch.setattr("src.config.MALSHARE_ENABLED", True)
    monkeypatch.setenv("MALSHARE_API_KEY", "k")
    mock_client = MagicMock()
    mock_client.list_pe32_hashes.return_value = [{"hash": "a" * 32}]
    with patch("src.sources.malshare.MalShareClient.from_config", return_value=mock_client):
        candidates = MalShareProvider().discover(3)
    assert len(candidates) == 1
    assert candidates[0].provider == "malshare"
    assert candidates[0].expected_label == 1

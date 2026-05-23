"""Tests for MalShareClient."""

from unittest.mock import MagicMock, patch

import pytest

from src.tools.clients.malshare_api_client import MalShareClient, MalShareUnavailable


def test_list_pe32_parses_json_list(monkeypatch):
    monkeypatch.setenv("MALSHARE_API_KEY", "test-key")
    client = MalShareClient(api_key="test-key")
    response = MagicMock()
    response.json.return_value = [{"md5": "a" * 32}, {"sha256": "b" * 64}]
    with patch.object(client, "get", return_value=response):
        rows = client.list_pe32_hashes(limit=5)
    assert len(rows) == 2
    assert rows[0]["hash"] == "a" * 32


def test_download_returns_bytes(monkeypatch):
    monkeypatch.setenv("MALSHARE_API_KEY", "test-key")
    client = MalShareClient(api_key="test-key")
    response = MagicMock()
    response.content = b"MZ" + b"\x00" * 126
    with patch.object(client, "get", return_value=response):
        data = client.download("c" * 32)
    assert data.startswith(b"MZ")


def test_disabled_raises(monkeypatch):
    monkeypatch.setattr("src.config.MALSHARE_ENABLED", False)
    with pytest.raises(MalShareUnavailable):
        MalShareClient.from_config()

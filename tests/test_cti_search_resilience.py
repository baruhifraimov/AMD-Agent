"""Tests for CTI host blocklist and utility functions."""

from unittest.mock import MagicMock, patch

import httpx

from src.tools import cti_search
from src.tools.cti_search import extract_hash_contexts, fetch_public_text, is_public_url


def setup_function():
    cti_search.reset_host_blocklist()


def teardown_function():
    cti_search.reset_host_blocklist()


def test_host_blocklisted_after_429_skips_second_fetch():
    url = "https://blocked.example/article"
    response = MagicMock()
    response.status_code = 429
    response.iter_bytes = MagicMock()
    err = httpx.HTTPStatusError("429", request=MagicMock(), response=response)

    with patch("src.tools.cti_search.httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_stream = MagicMock()
        mock_stream.__enter__.side_effect = err
        mock_client.stream.return_value = mock_stream
        mock_client_cls.return_value = mock_client

        assert cti_search.fetch_public_text(url) == ""
        assert cti_search.fetch_public_text(url) == ""
        assert mock_client.stream.call_count == 1


def test_extract_hash_contexts():
    sha = "a" * 64
    rows = extract_hash_contexts(f"malware sample sha256 {sha} windows pe loader")
    assert rows[0]["sha256"] == sha
    assert "loader" in rows[0]["context"]


def test_is_public_url_blocks_local_ranges():
    assert is_public_url("https://example.com/report")
    assert not is_public_url("http://127.0.0.1/report")
    assert not is_public_url("http://192.168.1.10/report")
    assert not is_public_url("file:///tmp/report")


def test_fetch_public_text_stream_truncates(httpx_mock, monkeypatch):
    monkeypatch.setattr("src.tools.cti_search.CTI_PAGE_MAX_BYTES", 32)
    httpx_mock.add_response(
        url="https://example.com/big",
        content=b"<html><body>" + b"a" * 1024 + b"</body></html>",
    )

    text = fetch_public_text("https://example.com/big")

    assert len(text) <= 32

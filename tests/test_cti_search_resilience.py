"""Tests for CTI host blocklist in fetch_public_text."""

from unittest.mock import MagicMock, patch

import httpx

from src.tools import cti_search


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


def test_web_search_passes_configured_ddgs_backend(monkeypatch):
    calls = {}

    class FakeDDGS:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def text(self, query, max_results=None, backend=None):
            calls["query"] = query
            calls["max_results"] = max_results
            calls["backend"] = backend
            return [
                {
                    "title": "Report",
                    "href": "https://example.com/report",
                    "body": "ioc context",
                }
            ]

    monkeypatch.setattr(cti_search, "BRAVE_SEARCH_API_KEY", "")
    monkeypatch.setattr(cti_search, "CTI_SEARCH_BACKENDS", "duckduckgo,brave")
    monkeypatch.setattr(cti_search, "_ddgs_client", lambda: FakeDDGS)

    rows = cti_search.web_search("malware hashes", limit=3)

    assert rows == [
        {
            "title": "Report",
            "url": "https://example.com/report",
            "snippet": "ioc context",
        }
    ]
    assert calls == {
        "query": "malware hashes",
        "max_results": 3,
        "backend": "duckduckgo,brave",
    }


def test_web_search_uses_brave_when_configured(httpx_mock, monkeypatch):
    monkeypatch.setattr(cti_search, "BRAVE_SEARCH_API_KEY", "test-token")
    httpx_mock.add_response(
        method="GET",
        url="https://api.search.brave.com/res/v1/web/search?q=malware&count=2&search_lang=en",
        json={
            "web": {
                "results": [
                    {
                        "title": "Threat report",
                        "url": "https://example.com/threat",
                        "description": "sha256 evidence",
                    }
                ]
            }
        },
    )

    rows = cti_search.web_search("malware", limit=2)

    assert rows == [
        {
            "title": "Threat report",
            "url": "https://example.com/threat",
            "snippet": "sha256 evidence",
        }
    ]


def test_web_search_falls_back_to_ddgs_when_brave_fails(monkeypatch):
    class FakeDDGS:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def text(self, query, max_results=None, backend=None):
            return [
                {
                    "title": "Fallback",
                    "href": "https://example.com/fallback",
                    "body": "fallback body",
                }
            ]

    monkeypatch.setattr(cti_search, "BRAVE_SEARCH_API_KEY", "test-token")
    monkeypatch.setattr(cti_search, "_brave_search", lambda query, limit: [])
    monkeypatch.setattr(cti_search, "_ddgs_client", lambda: FakeDDGS)

    rows = cti_search.web_search("malware", limit=2)

    assert rows[0]["url"] == "https://example.com/fallback"

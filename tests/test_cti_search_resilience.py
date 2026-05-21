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

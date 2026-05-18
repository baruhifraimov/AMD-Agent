"""Tests for Hybrid Strict dynamic CTI discovery."""

from unittest.mock import patch

from src.sources.dynamic_cti import DynamicCTIProvider
from src.tools.cti_search import extract_hash_contexts, fetch_public_text, is_public_url


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


@patch("src.sources.dynamic_cti.mb.is_pe_hash", return_value=True)
@patch("src.sources.dynamic_cti.semantic_filter_hashes")
@patch("src.sources.dynamic_cti.fetch_public_text")
@patch("src.sources.dynamic_cti.web_search")
@patch("src.sources.dynamic_cti.generate_cti_queries", return_value=["recent malware sha256"])
def test_dynamic_cti_discovers_hash_only_candidate(
    mock_queries,
    mock_search,
    mock_fetch,
    mock_filter,
    mock_is_pe,
):
    sha = "b" * 64
    mock_search.return_value = [
        {"title": "Report", "url": "https://example.com/cti", "snippet": "malware"}
    ]
    mock_fetch.return_value = f"Windows PE malware sample {sha}"
    mock_filter.return_value = [
        {
            "sha256": sha,
            "url": "https://example.com/cti",
            "context": "Windows PE malware sample",
            "semantic_reason": "malware PE",
        }
    ]

    candidates = DynamicCTIProvider().discover(limit=1)

    assert len(candidates) == 1
    assert candidates[0].provider == "dynamic_cti"
    assert candidates[0].download_ref["sha256"] == sha
    assert candidates[0].metadata["origin_url"] == "https://example.com/cti"


@patch("src.sources.dynamic_cti.time.sleep")
@patch("src.sources.dynamic_cti.web_search", return_value=[])
@patch("src.sources.dynamic_cti.generate_cti_queries", return_value=["q1", "q2", "q3"])
def test_dynamic_cti_jitters_between_queries(mock_queries, mock_search, mock_sleep):
    DynamicCTIProvider().discover(limit=1)

    assert mock_sleep.call_count == 2
    mock_sleep.assert_any_call(2.0)

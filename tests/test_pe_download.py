"""Tests for multi-provider PE download."""

from unittest.mock import MagicMock, patch

import pytest

from src.sources.base import SampleCandidate
from src.tools.pe_download import download_pe_candidate


@patch("src.tools.pe_download.mb.download_sample")
def test_download_mb_primary(mock_dl, minimal_pe_path):
    mock_dl.return_value = minimal_pe_path.path.read_bytes()
    cand = SampleCandidate(
        external_id=minimal_pe_path.sha256,
        provider="malwarebazaar",
        expected_label=1,
        download_ref={"sha256": minimal_pe_path.sha256},
    )
    data = download_pe_candidate(cand)
    assert data[:2] == b"MZ"


@patch("src.tools.pe_download.mb.download_sample", side_effect=RuntimeError("502"))
@patch("src.tools.pe_download._download_direct_url")
def test_download_fallback_url(mock_direct, mock_mb, minimal_pe_path):
    mock_direct.return_value = minimal_pe_path.path.read_bytes()
    cand = SampleCandidate(
        external_id="https://github.com/x/y.exe",
        provider="intel_direct",
        expected_label=1,
        download_ref={"fallback_url": "https://github.com/x/y.exe"},
    )
    data = download_pe_candidate(cand)
    assert data[:2] == b"MZ"
    mock_direct.assert_called_once()

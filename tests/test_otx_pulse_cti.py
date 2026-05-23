"""Tests for OTX Pulse CTI provider."""

from unittest.mock import MagicMock, patch

from src.sources.otx_pulse_cti import OTXPulseCTIProvider


@patch("src.sources.otx_pulse_cti.mb.is_pe_hash", return_value=True)
@patch("src.sources.otx_pulse_cti.semantic_filter_hashes")
@patch("src.sources.otx_pulse_cti.OTX_API_KEY", "test-key")
@patch("src.sources.otx_pulse_cti.OTX_ENABLED", True)
def test_otx_discovers_from_pulse_indicators(mock_filter, mock_is_pe, tmp_paths):
    sha = "b" * 64
    mock_filter.return_value = [
        {
            "sha256": sha,
            "context": "Emotet dropper campaign",
            "semantic_reason": "malware PE loader",
            "malware_family": "Emotet",
        }
    ]

    pulse = {
        "pulse_id": "p1",
        "pulse_name": "Emotet Campaign",
        "description": "New Emotet dropper",
        "tags": ["emotet"],
        "sha256_hashes": [sha],
        "raw_text": "Emotet dropper campaign with SHA256 indicators",
    }
    with patch("src.tools.clients.otx_api_client.OTXApiClient") as mock_client_cls:
        mock_client_cls.return_value.get_recent_pulses.return_value = [pulse]
        candidates = OTXPulseCTIProvider().discover(limit=5)

    assert len(candidates) == 1
    assert candidates[0].provider == "otx_pulse_cti"
    assert candidates[0].download_ref["sha256"] == sha
    assert candidates[0].metadata["discovery_source"] == "otx_pulse_cti"

    mock_filter.assert_called_once()
    evidence = mock_filter.call_args[0][0]
    assert len(evidence) == 1
    assert evidence[0]["sha256"] == sha
    assert "Emotet" in evidence[0]["context"]


@patch("src.sources.otx_pulse_cti.OTX_API_KEY", "test-key")
@patch("src.sources.otx_pulse_cti.OTX_ENABLED", True)
def test_otx_returns_empty_when_no_pulses(tmp_paths):
    with patch("src.tools.clients.otx_api_client.OTXApiClient") as mock_client_cls:
        mock_client_cls.return_value.get_recent_pulses.return_value = []
        candidates = OTXPulseCTIProvider().discover(limit=5)
    assert candidates == []


@patch("src.sources.otx_pulse_cti.semantic_filter_hashes", return_value=[])
@patch("src.sources.otx_pulse_cti.OTX_API_KEY", "test-key")
@patch("src.sources.otx_pulse_cti.OTX_ENABLED", True)
def test_otx_returns_empty_when_semantic_filter_rejects_all(mock_filter, tmp_paths):
    sha = "c" * 64
    pulse = {
        "pulse_id": "p2",
        "pulse_name": "Benign report",
        "description": "Not malware",
        "tags": [],
        "sha256_hashes": [sha],
        "raw_text": "Document hash for reference",
    }
    with patch("src.tools.clients.otx_api_client.OTXApiClient") as mock_client_cls:
        mock_client_cls.return_value.get_recent_pulses.return_value = [pulse]
        candidates = OTXPulseCTIProvider().discover(limit=5)
    assert candidates == []
    mock_filter.assert_called_once()


def test_otx_disabled_returns_empty():
    with patch("src.sources.otx_pulse_cti.OTX_ENABLED", False):
        candidates = OTXPulseCTIProvider().discover(limit=5)
    assert candidates == []


def test_otx_no_api_key_returns_empty():
    with patch("src.sources.otx_pulse_cti.OTX_API_KEY", ""):
        candidates = OTXPulseCTIProvider().discover(limit=5)
    assert candidates == []


@patch("src.sources.otx_pulse_cti.mb.is_pe_hash", return_value=True)
@patch("src.sources.otx_pulse_cti.semantic_filter_hashes")
@patch("src.sources.otx_pulse_cti.OTX_API_KEY", "test-key")
@patch("src.sources.otx_pulse_cti.OTX_ENABLED", True)
def test_otx_deduplicates_hashes_across_pulses(mock_filter, mock_is_pe, tmp_paths):
    sha = "d" * 64
    mock_filter.return_value = [
        {"sha256": sha, "context": "malware", "semantic_reason": "ok"},
    ]
    pulse1 = {"sha256_hashes": [sha], "raw_text": "pulse 1 text"}
    pulse2 = {"sha256_hashes": [sha], "raw_text": "pulse 2 text"}
    with patch("src.tools.clients.otx_api_client.OTXApiClient") as mock_client_cls:
        mock_client_cls.return_value.get_recent_pulses.return_value = [pulse1, pulse2]
        candidates = OTXPulseCTIProvider().discover(limit=5)
    assert len(candidates) == 1

    evidence = mock_filter.call_args[0][0]
    assert len(evidence) == 1

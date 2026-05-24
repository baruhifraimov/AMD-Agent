"""Tests for ThreatFox tool and provider."""

from unittest.mock import patch

from src.sources.threatfox import ThreatFoxProvider, _is_likely_pe
from src.tools import threatfox_api as tf


def test_extract_sha256_from_ioc_row():
    row = {
        "ioc": "a" * 64,
        "ioc_type": "sha256_hash",
        "malware": "win.test",
        "first_seen": "2024-01-01",
    }
    assert tf._extract_sha256(row) == "a" * 64


def test_get_recent_sha256_hashes_filters_domains(httpx_mock, monkeypatch):
    monkeypatch.setattr("src.tools.clients.threatfox_api_client.get_auth_key", lambda: "test-key")
    httpx_mock.add_response(
        url=tf.API_URL,
        method="POST",
        json={
            "query_status": "ok",
            "data": [
                {
                    "ioc": "evil.com",
                    "ioc_type": "domain",
                    "malware": "win.test",
                },
                {
                    "ioc": "b" * 64,
                    "ioc_type": "sha256_hash",
                    "malware_printable": "TestMal",
                    "first_seen": "2024-01-02",
                    "threat_type": "payload",
                },
            ],
        },
    )
    rows = tf.get_recent_sha256_hashes(days=3, limit=10)
    assert len(rows) == 1
    assert rows[0]["sha256"] == "b" * 64


@patch("src.sources.threatfox.mb.is_pe_hash", return_value=True)
@patch("src.sources.threatfox.tf.get_recent_sha256_hashes")
def test_threatfox_provider_discover(mock_get, _mock_pe):
    mock_get.return_value = [
        {
            "sha256": "c" * 64,
            "malware": "Family",
            "first_seen": "2024-01-01",
            "threat_type": "payload",
        }
    ]
    candidates = ThreatFoxProvider().discover(limit=5)
    assert len(candidates) == 1
    assert candidates[0].provider == "threatfox"
    assert candidates[0].download_ref["sha256"] == "c" * 64


@patch("src.sources.threatfox.mb.is_pe_hash", return_value=False)
@patch("src.sources.threatfox.tf.get_recent_sha256_hashes")
def test_threatfox_provider_skips_non_pe_mb(mock_get, _mock_pe):
    mock_get.return_value = [{"sha256": "d" * 64, "malware": "", "first_seen": "", "threat_type": ""}]
    assert ThreatFoxProvider().discover(limit=5) == []


def test_get_social_sha256_hashes_filters_by_twitter_reference(httpx_mock, monkeypatch):
    monkeypatch.setattr("src.tools.clients.threatfox_api_client.get_auth_key", lambda: "test-key")
    httpx_mock.add_response(
        url=tf.API_URL,
        method="POST",
        json={
            "query_status": "ok",
            "data": [
                {
                    "ioc": "f" * 64,
                    "ioc_type": "sha256_hash",
                    "reference": "https://twitter.com/user/status/1",
                    "malware_printable": "SocialMal",
                    "first_seen": "2024-01-03",
                },
                {
                    "ioc": "g" * 64,
                    "ioc_type": "sha256_hash",
                    "reference": "https://example.com/report",
                    "first_seen": "2024-01-03",
                },
            ],
        },
    )
    rows = tf.get_social_sha256_hashes(days=3, limit=10)
    assert len(rows) == 1
    assert rows[0]["sha256"] == "f" * 64
    assert "twitter.com" in rows[0]["reference"]


# --- _is_likely_pe heuristic ---

def test_is_likely_pe_exe_tag():
    assert _is_likely_pe({"tags": ["exe"], "malware": "unknown", "threat_type": "botnet_cc"})


def test_is_likely_pe_dll_tag():
    assert _is_likely_pe({"tags": ["dll"], "malware": "", "threat_type": ""})


def test_is_likely_pe_win_family_payload():
    assert _is_likely_pe({"tags": [], "malware": "win.mirai", "threat_type": "payload"})


def test_is_likely_pe_win64_family_payload():
    assert _is_likely_pe({"tags": [], "malware": "win64.agent", "threat_type": "payload"})


def test_is_likely_pe_win_family_non_payload():
    assert not _is_likely_pe({"tags": [], "malware": "win.mirai", "threat_type": "botnet_cc"})


def test_is_likely_pe_no_signals():
    assert not _is_likely_pe({"tags": ["banker"], "malware": "linux.botnet", "threat_type": "payload"})


def test_is_likely_pe_empty():
    assert not _is_likely_pe({})


def test_get_recent_sha256_hashes_includes_tags(httpx_mock, monkeypatch):
    monkeypatch.setattr("src.tools.clients.threatfox_api_client.get_auth_key", lambda: "test-key")
    httpx_mock.add_response(
        url=tf.API_URL,
        method="POST",
        json={
            "query_status": "ok",
            "data": [
                {
                    "ioc": "h" * 64,
                    "ioc_type": "sha256_hash",
                    "malware_printable": "TestMal",
                    "first_seen": "2024-01-04",
                    "threat_type": "payload",
                    "tags": ["exe", "banker"],
                }
            ],
        },
    )
    rows = tf.get_recent_sha256_hashes(days=3, limit=10)
    assert len(rows) == 1
    assert rows[0]["tags"] == ["exe", "banker"]


@patch("src.sources.threatfox.mb.is_pe_hash")
@patch("src.sources.threatfox.mb.malwarebazaar_available", return_value=True)
@patch("src.sources.threatfox.tf.get_recent_sha256_hashes")
def test_threatfox_skips_mb_check_for_pe_tagged(mock_get, _mock_avail, mock_is_pe):
    mock_get.return_value = [
        {
            "sha256": "i" * 64,
            "malware": "win.agent",
            "first_seen": "2024-01-01",
            "threat_type": "payload",
            "tags": ["exe"],
        }
    ]
    candidates = ThreatFoxProvider().discover(limit=5)
    assert len(candidates) == 1
    mock_is_pe.assert_not_called()

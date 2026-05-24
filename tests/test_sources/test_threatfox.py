"""Tests for ThreatFox tool and provider."""

from unittest.mock import patch

import httpx
import pytest

from src.sources.threatfox import ThreatFoxProvider, _is_likely_pe
from src.tools import threatfox_api as tf
from src.tools.clients.threatfox_api_client import ThreatFoxClient


@pytest.fixture(autouse=True)
def reset_threatfox_client():
    tf._client = None
    yield
    tf._client = None


@pytest.fixture(autouse=True)
def fast_http_backoff(monkeypatch):
    monkeypatch.setattr("src.tools.clients.http_client_base.time.sleep", lambda _seconds: None)


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


def test_get_recent_sha256_hashes_malware_samples_fanout(httpx_mock, monkeypatch):
    monkeypatch.setattr("src.tools.clients.threatfox_api_client.get_auth_key", lambda: "test-key")
    sha_a = "a" * 64
    sha_b = "b" * 64
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
                    "first_seen": "2024-01-01",
                    "threat_type": "payload",
                    "tags": ["exe"],
                    "malware_samples": [
                        {
                            "sha256_hash": sha_a,
                            "malware_bazaar": f"https://bazaar.abuse.ch/sample/{sha_a}/",
                        },
                        {"sha256_hash": sha_b},
                    ],
                }
            ],
        },
    )
    rows = tf.get_recent_sha256_hashes(days=3, limit=10, scan_budget=50)
    assert len(rows) == 2
    shas = {row["sha256"] for row in rows}
    assert shas == {sha_a, sha_b}
    mb_linked = {row["sha256"]: row["mb_linked"] for row in rows}
    assert mb_linked[sha_a] is True
    assert mb_linked[sha_b] is False


def test_get_recent_sha256_hashes_scan_budget_finds_late_hash(httpx_mock, monkeypatch):
    monkeypatch.setattr("src.tools.clients.threatfox_api_client.get_auth_key", lambda: "test-key")
    filler = [{"ioc": f"host{i}.com", "ioc_type": "domain"} for i in range(10)]
    target_sha = "c" * 64
    httpx_mock.add_response(
        url=tf.API_URL,
        method="POST",
        json={
            "query_status": "ok",
            "data": [
                *filler,
                {
                    "ioc": target_sha,
                    "ioc_type": "sha256_hash",
                    "malware_printable": "LateMal",
                    "first_seen": "2024-01-05",
                    "threat_type": "payload",
                },
            ],
        },
    )
    rows = tf.get_recent_sha256_hashes(days=3, limit=1, scan_budget=15)
    assert len(rows) == 1
    assert rows[0]["sha256"] == target_sha


def test_get_recent_sha256_hashes_taginfo_fallback_when_get_iocs_fails(httpx_mock, monkeypatch):
    import src.config as app_config

    monkeypatch.setattr("src.tools.clients.threatfox_api_client.get_auth_key", lambda: "test-key")
    monkeypatch.setattr(app_config, "THREATFOX_TAG_QUERIES", ("exe",))
    httpx_mock.add_exception(httpx.RemoteProtocolError("incomplete chunked read"))
    httpx_mock.add_response(
        url=tf.API_URL,
        method="POST",
        json={
            "query_status": "ok",
            "data": [
                {
                    "ioc": "e" * 64,
                    "ioc_type": "sha256_hash",
                    "tags": ["exe"],
                    "malware_printable": "TagMal",
                    "first_seen": "2024-01-06",
                    "threat_type": "payload",
                }
            ],
        },
    )
    rows = tf.get_recent_sha256_hashes(days=3, limit=5, scan_budget=50)
    assert len(rows) == 1
    assert rows[0]["sha256"] == "e" * 64
    assert len(httpx_mock.get_requests()) == 2


def test_post_form_retries_transport_error(httpx_mock, monkeypatch):
    monkeypatch.setattr("src.tools.clients.threatfox_api_client.get_auth_key", lambda: "test-key")
    httpx_mock.add_exception(httpx.RemoteProtocolError("incomplete chunked read"))
    httpx_mock.add_exception(httpx.RemoteProtocolError("incomplete chunked read"))
    httpx_mock.add_response(
        url=tf.API_URL,
        method="POST",
        json={"query_status": "ok", "data": []},
    )
    payload = ThreatFoxClient()._post_json({"query": "taginfo", "tag": "exe", "limit": 1})
    assert payload.get("query_status") == "ok"
    assert len(httpx_mock.get_requests()) == 3


def test_get_iocs_days_clamped_in_quick_fetch(httpx_mock, monkeypatch):
    monkeypatch.setattr("src.tools.clients.threatfox_api_client.get_auth_key", lambda: "test-key")
    httpx_mock.add_response(
        url=tf.API_URL,
        method="POST",
        json={"query_status": "ok", "data": []},
    )
    ThreatFoxClient()._fetch_get_iocs_payload(99)
    request = httpx_mock.get_requests()[0]
    assert request.content
    assert b'"days":7' in request.content.replace(b" ", b"")


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
                    "ioc": "a" * 63 + "b",
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
                    "ioc": "a" * 64,
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


@patch("src.sources.threatfox.mb.is_pe_hash", return_value=True)
@patch("src.sources.threatfox.mb.malwarebazaar_available", return_value=True)
@patch("src.sources.threatfox.tf.get_recent_sha256_hashes")
def test_threatfox_calls_mb_check_for_pe_tagged_when_mb_up(mock_get, _mock_avail, mock_is_pe):
    mock_get.return_value = [
        {
            "sha256": "e" * 64,
            "malware": "win.agent",
            "first_seen": "2024-01-01",
            "threat_type": "payload",
            "tags": ["exe"],
        }
    ]
    candidates = ThreatFoxProvider().discover(limit=5)
    assert len(candidates) == 1
    mock_is_pe.assert_called_once()


@patch("src.sources.threatfox.mb.is_pe_hash")
@patch("src.sources.threatfox.mb.malwarebazaar_available", return_value=False)
@patch("src.sources.threatfox.tf.get_recent_sha256_hashes")
def test_threatfox_skips_mb_check_for_pe_tagged_when_circuit_open(mock_get, _mock_avail, mock_is_pe):
    mock_get.return_value = [
        {
            "sha256": "e" * 64,
            "malware": "win.agent",
            "first_seen": "2024-01-01",
            "threat_type": "payload",
            "tags": ["exe"],
        }
    ]
    candidates = ThreatFoxProvider().discover(limit=5)
    assert len(candidates) == 1
    mock_is_pe.assert_not_called()


@patch("src.sources.threatfox.mb.is_pe_hash")
@patch("src.sources.threatfox.mb.malwarebazaar_available", return_value=False)
@patch("src.sources.threatfox.tf.get_recent_sha256_hashes")
def test_threatfox_accepts_mb_linked_when_circuit_open(mock_get, _mock_avail, mock_is_pe):
    sha = "f" * 64
    mock_get.return_value = [
        {
            "sha256": sha,
            "malware": "",
            "first_seen": "",
            "threat_type": "",
            "mb_linked": True,
        }
    ]
    candidates = ThreatFoxProvider().discover(limit=5)
    assert len(candidates) == 1
    assert candidates[0].download_ref.get("mb_linked") is True
    mock_is_pe.assert_not_called()


@patch("src.sources.threatfox.mb.is_pe_hash")
@patch("src.sources.threatfox.mb.malwarebazaar_available", return_value=False)
@patch("src.sources.threatfox.tf.get_recent_sha256_hashes")
def test_threatfox_skips_untagged_when_circuit_open(mock_get, _mock_avail, mock_is_pe):
    mock_get.return_value = [
        {"sha256": "0" * 64, "malware": "", "first_seen": "", "threat_type": "", "mb_linked": False},
    ]
    assert ThreatFoxProvider().discover(limit=5) == []
    mock_is_pe.assert_not_called()

"""Live ThreatFox integration tests (optional; requires MALWAREBAZAAR_AUTH_KEY)."""

from __future__ import annotations

import os

import pytest

from src.config import get_auth_key
from src.sources.threatfox import ThreatFoxProvider
from src.tools import threatfox_api as tf


_LIVE_KEY = os.getenv("MALWAREBAZAAR_AUTH_KEY", "test-key")
_SKIP_LIVE = _LIVE_KEY in ("", "test-key")


@pytest.mark.integration
@pytest.mark.skipif(_SKIP_LIVE, reason="set real MALWAREBAZAAR_AUTH_KEY for live ThreatFox tests")
def test_live_threatfox_discover_returns_candidates():
    get_auth_key()
    tf._client = None
    rows = tf.get_recent_sha256_hashes(limit=3, scan_budget=50)
    assert rows, "expected ThreatFox hashes via get_iocs or taginfo fallback"
    candidates = ThreatFoxProvider().discover(3)
    assert candidates


@pytest.mark.integration
@pytest.mark.skipif(_SKIP_LIVE, reason="set real MALWAREBAZAAR_AUTH_KEY for live ThreatFox tests")
def test_live_threatfox_download_pe_if_mb_has_sample():
    get_auth_key()
    from src.tools import malwarebazaar_api as mb
    from src.tools.pe_download import download_pe_candidate

    tf._client = None
    for candidate in ThreatFoxProvider().discover(15):
        if not mb.malwarebazaar_available():
            pytest.skip("MalwareBazaar circuit open")
        if not mb.is_pe_hash(candidate.external_id):
            continue
        data = download_pe_candidate(candidate)
        assert data[:2] == b"MZ"
        return
    pytest.skip("no ThreatFox candidate with MalwareBazaar PE sample in this window")

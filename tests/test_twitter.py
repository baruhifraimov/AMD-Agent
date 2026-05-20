"""Tests for Twitter CTI provider."""

from unittest.mock import patch

from src.sources.twitter import TwitterProvider


@patch("src.sources.twitter.mb.is_pe_hash", return_value=True)
@patch("src.sources.twitter.tf.get_social_sha256_hashes")
def test_twitter_provider_discover(mock_get, _mock_pe):
    mock_get.return_value = [
        {
            "sha256": "a" * 64,
            "malware": "Family",
            "first_seen": "2024-01-01",
            "threat_type": "payload",
            "reference": "https://x.com/ioc/status/1",
        }
    ]
    candidates = TwitterProvider().discover(limit=5)
    assert len(candidates) == 1
    assert candidates[0].provider == "twitter"
    assert candidates[0].metadata["discovery_source"] == "twitter_cti"

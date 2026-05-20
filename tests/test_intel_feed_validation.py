"""Tests for RSS feed URL validation."""

from src.intel.rss import is_valid_feed_url


def test_is_valid_feed_url_rejects_bare_homepage():
    assert is_valid_feed_url("https://code.kx.com") is False
    assert is_valid_feed_url("https://example.com/blog/post") is False


def test_is_valid_feed_url_accepts_feed_paths():
    assert is_valid_feed_url("https://example.com/feed/") is True
    assert is_valid_feed_url("https://example.com/rss.xml") is True

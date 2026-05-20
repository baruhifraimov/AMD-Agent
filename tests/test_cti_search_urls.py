"""Tests for PE URL extraction from CTI text."""

from src.tools.cti_search import extract_pe_urls


def test_extract_pe_urls_allowlisted():
    text = "Download at https://github.com/org/repo/releases/download/v1/sample.exe for analysis"
    urls = extract_pe_urls(text)
    assert any("github.com" in u for u in urls)


def test_extract_pe_urls_skips_non_allowlisted():
    text = "Get it at https://evil.example/malware.exe"
    urls = extract_pe_urls(text)
    assert urls == []

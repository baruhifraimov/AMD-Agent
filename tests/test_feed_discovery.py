"""Tests for CTI source discovery filtering."""

from src.intel.feed_discovery import is_low_signal_cti_url, is_precise_intel_source_url


def test_low_signal_cti_hosts_are_filtered():
    assert is_low_signal_cti_url("https://www.sciencedirect.com/science/article/pii/example")
    assert is_low_signal_cti_url("https://link.springer.com/article/10.1000/example")
    assert is_low_signal_cti_url("https://arxiv.org/abs/2505.24231")
    assert is_low_signal_cti_url("https://medium.com/@x/malware-analysis-the-pe-structure-overview")
    assert is_low_signal_cti_url(
        "https://github.com/CommodoreAlex/Malware-Analysis-and-Reverse-Engineering/blob/main/manualpe.md"
    )
    assert not is_low_signal_cti_url("https://thedfirreport.com/feed/")


def test_precise_intel_sources_are_feed_only():
    assert is_precise_intel_source_url("https://thedfirreport.com/feed/")
    assert is_precise_intel_source_url("https://www.malwarebytes.com/blog/feed")
    assert not is_precise_intel_source_url("https://thedfirreport.com/2024/08/26/post/")
    assert not is_precise_intel_source_url("https://github.com/org/ioc-list")

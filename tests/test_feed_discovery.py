"""Tests for CTI source discovery filtering."""

from src.intel.feed_discovery import is_low_signal_cti_url


def test_low_signal_cti_hosts_are_filtered():
    assert is_low_signal_cti_url("https://www.sciencedirect.com/science/article/pii/example")
    assert is_low_signal_cti_url("https://link.springer.com/article/10.1000/example")
    assert not is_low_signal_cti_url("https://thedfirreport.com/feed/")

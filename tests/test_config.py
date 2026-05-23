"""Tests for runtime configuration."""

import src.config as config


def test_pe_fetch_limit_default():
    assert config.PE_FETCH_LIMIT == 10


def test_malware_fallback_providers_default():
    assert config.MALWARE_FALLBACK_PROVIDERS == ("malshare", "threatfox", "dynamic_cti")


def test_mb_min_request_interval_default():
    assert config.MB_MIN_REQUEST_INTERVAL == 1.5


def test_fallback_pe_check_mult_default():
    assert config.FALLBACK_PE_CHECK_MULT == 1


def test_scheduler_defaults():
    assert config.SCHED_INTERVAL_SECONDS == 1800
    assert config.SCHED_MAX_RUNS is None

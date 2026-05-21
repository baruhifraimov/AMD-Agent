"""Tests for runtime configuration."""

import importlib

import src.config as config


def test_pe_fetch_limit_env(monkeypatch):
    monkeypatch.setenv("AMD_PE_FETCH_LIMIT", "7")
    reloaded = importlib.reload(config)
    try:
        assert reloaded.PE_FETCH_LIMIT == 7
    finally:
        monkeypatch.delenv("AMD_PE_FETCH_LIMIT", raising=False)
        importlib.reload(config)


def test_malware_fallback_providers_env(monkeypatch):
    monkeypatch.setenv("AMD_MALWARE_FALLBACK_PROVIDERS", "threatfox,dynamic_cti")
    reloaded = importlib.reload(config)
    try:
        assert reloaded.MALWARE_FALLBACK_PROVIDERS == ("threatfox", "dynamic_cti")
    finally:
        monkeypatch.delenv("AMD_MALWARE_FALLBACK_PROVIDERS", raising=False)
        importlib.reload(config)


def test_fallback_pe_check_mult_env(monkeypatch):
    monkeypatch.setenv("AMD_FALLBACK_PE_CHECK_MULT", "2")
    reloaded = importlib.reload(config)
    try:
        assert reloaded.FALLBACK_PE_CHECK_MULT == 2
    finally:
        monkeypatch.delenv("AMD_FALLBACK_PE_CHECK_MULT", raising=False)
        importlib.reload(config)

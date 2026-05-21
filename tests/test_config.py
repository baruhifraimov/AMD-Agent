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

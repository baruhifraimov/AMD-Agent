"""Tests for dynamic ThreatIngestor sleep interval."""

from unittest.mock import patch

from src.collection.context import current_collection_phase
from src.intel.threatingestor_sleep import (
    bootstrap_collection_complete,
    threatingestor_interval_seconds,
    write_runtime_config,
)


def test_interval_bootstrap_when_targets_not_met(tmp_paths, monkeypatch):
    monkeypatch.setattr(
        "src.intel.threatingestor_sleep.THREATINGESTOR_SLEEP_BOOTSTRAP",
        45,
    )
    monkeypatch.setattr(
        "src.intel.threatingestor_sleep.THREATINGESTOR_SLEEP_STEADY",
        900,
    )
    assert threatingestor_interval_seconds(tmp_paths["tracker"]) == 45
    assert bootstrap_collection_complete(tmp_paths["tracker"]) is False


@patch("src.intel.threatingestor_sleep.training_targets_met", return_value=True)
def test_interval_steady_after_bootstrap(mock_met, tmp_paths, monkeypatch):
    monkeypatch.setattr(
        "src.intel.threatingestor_sleep.THREATINGESTOR_SLEEP_BOOTSTRAP",
        45,
    )
    monkeypatch.setattr(
        "src.intel.threatingestor_sleep.THREATINGESTOR_SLEEP_STEADY",
        900,
    )
    assert threatingestor_interval_seconds(tmp_paths["tracker"]) == 900
    assert bootstrap_collection_complete(tmp_paths["tracker"]) is True


def test_current_collection_phase_bootstrap_when_empty_db(tmp_paths):
    assert current_collection_phase(tmp_paths["tracker"]) == "bootstrap"


def test_write_runtime_config_sets_daemon_false(tmp_path):
    template = tmp_path / "ti.yml"
    template.write_text(
        "general:\n  daemon: true\n  sleep: 900\nsources: []\noperators: []\n",
        encoding="utf-8",
    )
    out = tmp_path / "runtime.yml"
    write_runtime_config(template_path=template, output_path=out)
    text = out.read_text(encoding="utf-8")
    assert "daemon: false" in text

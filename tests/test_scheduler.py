"""Tests for scheduler configuration and loop."""

from pathlib import Path

from src.runtime.scheduler import SchedulerConfig, SchedulerLoop, load_scheduler_config


def test_scheduler_config_from_env(monkeypatch):
    monkeypatch.setenv("AMD_SCHED_INTERVAL", "120")
    monkeypatch.setenv("AMD_SCHED_MAX_RUNS", "3")
    cfg = SchedulerConfig.from_env()
    assert cfg.interval_seconds == 120
    assert cfg.max_runs == 3


def test_load_scheduler_yaml_merge(tmp_path):
    path = tmp_path / "sched.yaml"
    path.write_text("interval_seconds: 600\njitter_seconds: 10\n")
    cfg = load_scheduler_config(path)
    assert cfg.interval_seconds == 600
    assert cfg.jitter_seconds == 10


def test_scheduler_should_stop_at_max_runs():
    cfg = SchedulerConfig(max_runs=3)
    loop = SchedulerLoop(cfg)
    assert not loop._should_stop(2)
    assert loop._should_stop(3)

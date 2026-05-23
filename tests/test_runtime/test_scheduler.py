"""Tests for scheduler configuration and loop."""

import logging
from pathlib import Path
from unittest.mock import patch

from src.runtime.scheduler import SchedulerConfig, SchedulerLoop, load_scheduler_config


def test_scheduler_config_from_config():
    with patch("src.config.SCHED_INTERVAL_SECONDS", 120), patch(
        "src.config.SCHED_MAX_RUNS", 3
    ):
        cfg = SchedulerConfig.from_config()
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


def test_scheduler_logs_idle_before_sleep(caplog):
    cfg = SchedulerConfig(
        interval_seconds=120,
        max_runs=2,
        run_on_start=False,
        jitter_seconds=0,
    )
    loop = SchedulerLoop(cfg)
    calls: list[int] = []

    def callback() -> None:
        calls.append(1)

    with caplog.at_level(logging.INFO), patch("src.runtime.scheduler.time.sleep"):
        loop.run(callback)

    assert len(calls) == 2
    idle_msgs = [r.message for r in caplog.records if "Idle" in r.message]
    assert len(idle_msgs) == 2
    assert "run #1" in idle_msgs[0]
    assert "interval=120" in idle_msgs[0]

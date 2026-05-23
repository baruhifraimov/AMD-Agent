"""Configurable scheduler loop for repeated graph invocation."""

from __future__ import annotations

import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import yaml
from pydantic import BaseModel, Field

from src import config
from src.log import PHASE_SCHEDULER, get_logger, phase_log, vlog

logger = get_logger(__name__)


def _wake_time_utc(seconds_from_now: float) -> str:
    wake = datetime.now(timezone.utc).timestamp() + seconds_from_now
    return datetime.fromtimestamp(wake, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class SchedulerConfig(BaseModel):
    enabled: bool = False
    interval_seconds: int = Field(default=1800, ge=1)
    max_runs: int | None = None
    run_on_start: bool = True
    jitter_seconds: int = Field(default=60, ge=0)
    error_backoff_seconds: int = Field(default=60, ge=1)
    max_backoff_seconds: int = Field(default=3600, ge=1)

    @classmethod
    def from_config(cls) -> SchedulerConfig:
        return cls(
            enabled=config.SCHED_ENABLED,
            interval_seconds=config.SCHED_INTERVAL_SECONDS,
            max_runs=config.SCHED_MAX_RUNS,
            run_on_start=config.SCHED_RUN_ON_START,
            jitter_seconds=config.SCHED_JITTER_SECONDS,
            error_backoff_seconds=config.SCHED_ERROR_BACKOFF_SECONDS,
            max_backoff_seconds=config.SCHED_MAX_BACKOFF_SECONDS,
        )


def load_scheduler_config(path: Path | None = None) -> SchedulerConfig:
    cfg = SchedulerConfig.from_config()
    if path is None or not path.exists():
        return cfg
    with path.open() as f:
        data = yaml.safe_load(f) or {}
    merged = {**cfg.model_dump(), **data}
    return SchedulerConfig.model_validate(merged)


class SchedulerLoop:
    def __init__(self, config: SchedulerConfig) -> None:
        self.config = config
        self._consecutive_errors = 0

    def run(self, callback: Callable[[], None]) -> None:
        runs = 0
        phase_log(
            logger,
            PHASE_SCHEDULER,
            "Started interval=%ds max_runs=%s",
            self.config.interval_seconds,
            self.config.max_runs,
        )
        if self.config.run_on_start:
            self._execute(callback)
            runs += 1
            if self._should_stop(runs):
                return

        while True:
            sleep_s = self._sleep_duration()
            self._log_idle_until_next_run(sleep_s, runs + 1)
            try:
                time.sleep(sleep_s)
            except KeyboardInterrupt:
                phase_log(logger, PHASE_SCHEDULER, "Interrupted during sleep")
                break

            self._execute(callback)
            runs += 1
            if self._should_stop(runs):
                break

        phase_log(logger, PHASE_SCHEDULER, "Stopped after %d runs", runs)

    def _log_idle_until_next_run(self, sleep_s: float, next_run_index: int) -> None:
        wake = _wake_time_utc(sleep_s)
        if self._consecutive_errors:
            phase_log(
                logger,
                PHASE_SCHEDULER,
                "Backing off %.0fs after %d consecutive error(s); run #%d at ~%s",
                sleep_s,
                self._consecutive_errors,
                next_run_index,
                wake,
            )
            return
        jitter_hi = self.config.jitter_seconds
        phase_log(
            logger,
            PHASE_SCHEDULER,
            "Idle %.0fs until run #%d at ~%s (interval=%ds, jitter=0-%ds)",
            sleep_s,
            next_run_index,
            wake,
            self.config.interval_seconds,
            jitter_hi,
        )
        vlog(logger, "info", "Scheduler sleep detail: %.3fs until run #%d", sleep_s, next_run_index)

    def _execute(self, callback: Callable[[], None]) -> None:
        start = time.monotonic()
        try:
            callback()
            self._consecutive_errors = 0
            phase_log(logger, PHASE_SCHEDULER, "Run OK (%.1fs)", time.monotonic() - start)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            self._consecutive_errors += 1
            logger.exception("[%s] Run failed: %s", PHASE_SCHEDULER, exc)

    def _sleep_duration(self) -> float:
        base = float(self.config.interval_seconds)
        jitter = random.uniform(0, float(self.config.jitter_seconds)) if self.config.jitter_seconds else 0.0
        if self._consecutive_errors == 0:
            return base + jitter
        backoff = min(
            self.config.error_backoff_seconds * (2 ** (self._consecutive_errors - 1)),
            self.config.max_backoff_seconds,
        )
        return backoff + jitter

    def _should_stop(self, runs: int) -> bool:
        if self.config.max_runs is not None and runs >= self.config.max_runs:
            phase_log(logger, PHASE_SCHEDULER, "Reached max_runs=%d", self.config.max_runs)
            return True
        return False

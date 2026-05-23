"""Configurable scheduler loop for repeated graph invocation."""

from __future__ import annotations

import logging
import random
import time
from pathlib import Path
from typing import Callable

import yaml
from pydantic import BaseModel, Field

from src import config

logger = logging.getLogger(__name__)


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
        logger.info(
            "Scheduler started interval=%ds max_runs=%s",
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
            logger.info("Scheduler sleeping %.1fs", sleep_s)
            try:
                time.sleep(sleep_s)
            except KeyboardInterrupt:
                logger.info("Scheduler interrupted during sleep")
                break

            self._execute(callback)
            runs += 1
            if self._should_stop(runs):
                break

        logger.info("Scheduler stopped after %d runs", runs)

    def _execute(self, callback: Callable[[], None]) -> None:
        start = time.monotonic()
        try:
            callback()
            self._consecutive_errors = 0
            logger.info("Scheduler run OK (%.1fs)", time.monotonic() - start)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            self._consecutive_errors += 1
            logger.exception("Scheduler run failed: %s", exc)

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
            logger.info("Scheduler reached max_runs=%d", self.config.max_runs)
            return True
        return False

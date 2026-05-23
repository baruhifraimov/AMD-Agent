"""Application logging: verbose console gating, phase summaries, file capture."""

from __future__ import annotations

import logging
import sys
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from typing import Iterator

import src.config as cfg

# Pipeline phase tags for regular-mode console output.
PHASE_PREFLIGHT = "PREFLIGHT"
PHASE_BOOTSTRAP = "BOOTSTRAP"
PHASE_SCHEDULER = "SCHEDULER"
PHASE_SELECT = "SELECT"
PHASE_DISCOVERY = "DISCOVERY"
PHASE_FETCH = "FETCH"
PHASE_VALIDATION = "VALIDATION"
PHASE_EXTRACTION = "EXTRACTION"
PHASE_DRIFT = "DRIFT"
PHASE_INFERENCE = "INFERENCE"
PHASE_RETRAIN = "RETRAIN"
PHASE_EVAL = "EVAL"
PHASE_ML = "ML"
PHASE_API = "API"
PHASE_LLM = "LLM"

_CONSOLE_FMT = "%(asctime)s %(levelname)s %(message)s"
_FILE_FMT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"

_NOISY_LOGGERS = (
    "httpx",
    "httpcore",
    "urllib3",
    "hpack",
    "langchain",
    "langchain_ollama",
)

_configured = False


class ConsoleFilter(logging.Filter):
    """Hide verbose-only records from console when VERBOSE is False."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "ollama_file_only", False):
            return False
        if getattr(record, "verbose_only", False):
            return cfg.VERBOSE
        return True


def configure_logging() -> None:
    """Configure console + rotating file handlers (idempotent)."""
    global _configured
    if _configured:
        return

    cfg.ensure_dirs()
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    for handler in list(root.handlers):
        root.removeHandler(handler)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(_CONSOLE_FMT, datefmt=_DATE_FMT))
    console.addFilter(ConsoleFilter())
    root.addHandler(console)

    file_handler = RotatingFileHandler(
        cfg.LOG_PATH,
        maxBytes=cfg.LOG_MAX_BYTES,
        backupCount=cfg.LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(_FILE_FMT, datefmt=_DATE_FMT))
    root.addHandler(file_handler)

    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a module logger after ensuring logging is configured."""
    configure_logging()
    return logging.getLogger(name)


def vlog(logger: logging.Logger, level: str, msg: str, *args: object, **kwargs: object) -> None:
    """Log per-item detail; console only when VERBOSE=True, always in file."""
    extra = dict(kwargs.pop("extra", {}) or {})
    extra["verbose_only"] = True
    getattr(logger, level)(msg, *args, extra=extra, **kwargs)


def ollama_file_only(logger: logging.Logger, level: str, msg: str, *args: object, **kwargs: object) -> None:
    """Ollama full payloads: log file only (never console)."""
    extra = dict(kwargs.pop("extra", {}) or {})
    extra["ollama_file_only"] = True
    getattr(logger, level)(msg, *args, extra=extra, **kwargs)


def phase_log(
    logger: logging.Logger,
    phase: str,
    msg: str,
    *args: object,
    level: str = "info",
    **kwargs: object,
) -> None:
    """Regular-mode friendly log with phase prefix."""
    getattr(logger, level)(f"[{phase}] {msg}", *args, **kwargs)


@contextmanager
def task_status(phase: str, message: str) -> Iterator[None]:
    """Rich spinner on TTY when not verbose; otherwise plain phase log."""
    configure_logging()
    logger = logging.getLogger("amd_agent.task")
    use_spinner = not cfg.VERBOSE and sys.stderr.isatty()

    if use_spinner:
        from rich.console import Console
        from rich.status import Status

        console = Console(stderr=True)
        with Status(f"[{phase}] {message}", console=console):
            yield
    else:
        phase_log(logger, phase, message)
        yield


def reset_logging_for_tests() -> None:
    """Tear down handlers so tests can reconfigure logging."""
    global _configured
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    _configured = False

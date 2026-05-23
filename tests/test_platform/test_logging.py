"""Logging configuration: verbose gating, file capture, third-party silencing."""

from __future__ import annotations

import logging

import httpx
import pytest

import src.config as cfg
from src.log import (
    ConsoleFilter,
    configure_logging,
    get_logger,
    phase_log,
    reset_logging_for_tests,
    vlog,
)


@pytest.fixture(autouse=True)
def _logging_isolation(tmp_path, monkeypatch):
    log_file = tmp_path / "amd-agent.log"
    monkeypatch.setattr(cfg, "LOG_PATH", log_file)
    reset_logging_for_tests()
    configure_logging()
    yield
    reset_logging_for_tests()


def test_configure_logging_idempotent_and_creates_file(tmp_path, monkeypatch):
    log_file = tmp_path / "test.log"
    monkeypatch.setattr(cfg, "LOG_PATH", log_file)
    reset_logging_for_tests()
    configure_logging()
    configure_logging()
    assert log_file.exists()


def test_console_filter_hides_verbose_when_not_verbose(monkeypatch):
    monkeypatch.setattr(cfg, "VERBOSE", False)
    filt = ConsoleFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="detail",
        args=(),
        exc_info=None,
    )
    record.verbose_only = True
    assert filt.filter(record) is False

    monkeypatch.setattr(cfg, "VERBOSE", True)
    assert filt.filter(record) is True


def test_file_receives_verbose_only_records(monkeypatch, tmp_path):
    monkeypatch.setattr(cfg, "LOG_PATH", tmp_path / "verbose.log")
    monkeypatch.setattr(cfg, "VERBOSE", False)
    reset_logging_for_tests()
    configure_logging()
    logger = get_logger("test.verbose.file")
    vlog(logger, "info", "hidden on console detail line")
    assert (tmp_path / "verbose.log").read_text(encoding="utf-8").count("hidden on console") == 1


def test_phase_log_formats_prefix():
    logger = get_logger("test.phase")
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    cap = _Capture()
    cap.setLevel(logging.INFO)
    logger.addHandler(cap)
    phase_log(logger, "FETCH", "Downloaded %d files", 3)
    assert records
    assert "[FETCH] Downloaded 3 files" in records[-1].getMessage()


def test_httpx_info_not_propagated_to_root_console():
  root = logging.getLogger()
  console_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)]
  assert console_handlers
  httpx_logger = logging.getLogger("httpx")
  assert httpx_logger.level >= logging.WARNING


def test_get_logger_configures_once():
    reset_logging_for_tests()
    a = get_logger("a")
    b = get_logger("b")
    assert a is not b
    assert logging.getLogger().handlers


def test_ollama_file_only_hidden_from_console(monkeypatch):
    monkeypatch.setattr(cfg, "VERBOSE", True)
    filt = ConsoleFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="payload",
        args=(),
        exc_info=None,
    )
    record.ollama_file_only = True
    assert filt.filter(record) is False


def test_invoke_chat_logs_lifecycle(monkeypatch, tmp_path):
    from src.llm import ollama_trace

    monkeypatch.setattr(cfg, "LOG_PATH", tmp_path / "ollama.log")
    monkeypatch.setattr(cfg, "OLLAMA_LOG_DETAIL", False)

    class _FakeResponse:
        content = '{"ok": true}'
        tool_calls = []

    class _FakeModel:
        def invoke(self, messages):
            return _FakeResponse()

    reset_logging_for_tests()
    configure_logging()
    ollama_trace.invoke_chat(
        _FakeModel(),
        [("system", "sys"), ("human", "hi")],
        operation="test_op",
    )
    log_text = (tmp_path / "ollama.log").read_text(encoding="utf-8")
    assert "test_op: sending to" in log_text
    assert "waiting for Ollama" in log_text
    assert "response OK" in log_text
    assert "request message[0] role=system" in log_text

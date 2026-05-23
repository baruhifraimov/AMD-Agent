"""Structured logging for Ollama HTTP/chat calls (lifecycle + payloads)."""

from __future__ import annotations

import json
import time
from typing import Any

import src.config as cfg
from src.config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT
from src.log import PHASE_LLM, get_logger, ollama_file_only, phase_log

logger = get_logger(__name__)


def _truncate(text: str, limit: int) -> str:
    text = text.replace("\r\n", "\n").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [{len(text)} chars total]"


def _format_messages(messages: list[Any]) -> list[dict[str, str]]:
    """Normalize LangChain-style message tuples to role/content dicts."""
    out: list[dict[str, str]] = []
    for item in messages:
        if isinstance(item, dict):
            role = str(item.get("role") or item.get("type") or "message")
            content = item.get("content", item)
            out.append({"role": role, "content": str(content)})
            continue
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            out.append({"role": str(item[0]), "content": str(item[1])})
            continue
        out.append({"role": "message", "content": str(item)})
    return out


def _log_messages(operation: str, messages: list[Any]) -> None:
    for idx, part in enumerate(_format_messages(messages)):
        role = part["role"]
        body = part["content"]
        ollama_file_only(
            logger,
            "info",
            "%s request message[%d] role=%s:\n%s",
            operation,
            idx,
            role,
            _truncate(body, cfg.OLLAMA_LOG_MAX_CHARS),
        )
        if cfg.OLLAMA_LOG_DETAIL:
            phase_log(
                logger,
                PHASE_LLM,
                "%s request[%d] %s: %s",
                operation,
                idx,
                role,
                _truncate(body, cfg.OLLAMA_LOG_CONSOLE_PREVIEW),
            )


def _log_response(operation: str, response: Any, elapsed_s: float) -> None:
    content = str(getattr(response, "content", "") or "")
    tool_calls = getattr(response, "tool_calls", None) or []
    phase_log(
        logger,
        PHASE_LLM,
        "%s: response OK in %.2fs (content=%d chars, tool_calls=%d)",
        operation,
        elapsed_s,
        len(content),
        len(tool_calls),
    )
    if content:
        ollama_file_only(
            logger,
            "info",
            "%s response content:\n%s",
            operation,
            _truncate(content, cfg.OLLAMA_LOG_MAX_CHARS),
        )
        if cfg.OLLAMA_LOG_DETAIL:
            phase_log(
                logger,
                PHASE_LLM,
                "%s response preview: %s",
                operation,
                _truncate(content, cfg.OLLAMA_LOG_CONSOLE_PREVIEW),
            )
    if tool_calls:
        try:
            tc_text = json.dumps(tool_calls, default=str, ensure_ascii=False)
        except TypeError:
            tc_text = str(tool_calls)
        ollama_file_only(logger, "info", "%s tool_calls:\n%s", operation, _truncate(tc_text, cfg.OLLAMA_LOG_MAX_CHARS))
        if cfg.OLLAMA_LOG_DETAIL:
            phase_log(
                logger,
                PHASE_LLM,
                "%s tool_calls preview: %s",
                operation,
                _truncate(tc_text, cfg.OLLAMA_LOG_CONSOLE_PREVIEW),
            )


def invoke_chat(
    model: Any,
    messages: list[Any],
    *,
    operation: str,
    bind_tools: list[Any] | None = None,
) -> Any:
    """Invoke ChatOllama with full request/response tracing."""
    tool_count = len(bind_tools) if bind_tools else 0
    phase_log(
        logger,
        PHASE_LLM,
        "%s: sending to %s model=%s timeout=%ss tools=%d",
        operation,
        OLLAMA_BASE_URL,
        OLLAMA_MODEL,
        OLLAMA_TIMEOUT,
        tool_count,
    )
    _log_messages(operation, messages)
    phase_log(logger, PHASE_LLM, "%s: waiting for Ollama response...", operation)

    started = time.monotonic()
    try:
        runner = model.bind_tools(bind_tools) if bind_tools else model
        response = runner.invoke(messages)
    except Exception as exc:
        elapsed = time.monotonic() - started
        phase_log(
            logger,
            PHASE_LLM,
            "%s: request failed after %.2fs: %s",
            operation,
            elapsed,
            exc,
            level="warning",
        )
        raise

    _log_response(operation, response, time.monotonic() - started)
    return response

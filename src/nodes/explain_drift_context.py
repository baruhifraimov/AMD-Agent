"""Explain drift context using capa + best-effort Ollama reporting."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from src.config import CAPA_RULES_DIR
from src.llm import summarize_capa_findings
from src.state import AgentState

logger = logging.getLogger(__name__)

CAPA_TIMEOUT_SECONDS = 300
CAPA_SAMPLE_LIMIT = 3
CAPA_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB


def explain_drift_context(state: AgentState) -> dict:
    capa_results: dict[str, dict] = dict(state.capa_results)
    for path in state.downloaded_paths[:CAPA_SAMPLE_LIMIT]:
        sha = Path(path).stem.lower()
        if sha in capa_results:
            continue
        size = Path(path).stat().st_size if Path(path).exists() else 0
        if size > CAPA_MAX_FILE_BYTES:
            logger.info("capa skipped %s: file too large (%d MB)", sha[:16], size // (1024 * 1024))
            capa_results[sha] = {"error": f"skipped: file too large ({size // (1024*1024)} MB)"}
            continue
        capa_results[sha] = _run_capa(path)

    report = summarize_capa_findings(capa_results, state.feature_vectors)
    return {"semantic_report": report, "capa_results": capa_results}


def _run_capa(path: str) -> dict:
    command = ["capa", "-j", "-r", str(CAPA_RULES_DIR), "-s", "/opt/capa-sigs", path]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=CAPA_TIMEOUT_SECONDS,
            check=False,
        )
    except Exception as exc:
        logger.warning("capa execution failed for %s: %s", path, exc)
        return {"error": str(exc), "command": command}

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        logger.warning("capa failed for %s: %s", path, stderr)
        return {
            "error": stderr or f"capa exited with {completed.returncode}",
            "returncode": completed.returncode,
            "command": command,
        }

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        logger.warning("capa returned invalid JSON for %s: %s", path, exc)
        return {
            "error": f"invalid capa JSON: {exc}",
            "stdout": completed.stdout[:2000],
            "command": command,
        }

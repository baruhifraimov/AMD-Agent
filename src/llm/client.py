"""Best-effort Ollama integration with deterministic fallbacks.

The pipeline must remain usable when Ollama is unavailable. Public helpers
therefore return None or conservative defaults instead of raising.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from src.config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT, REPORT_LANGUAGE

logger = logging.getLogger(__name__)


class SourceDecision(BaseModel):
    source_type: str
    selected_sources: list[str] = Field(default_factory=list)
    expected_label: int
    discovery_strategy: str = ""
    cti_queries: list[str] = Field(default_factory=list)


def _ollama_disabled() -> bool:
    return os.getenv("AMD_OLLAMA_ENABLED", "1").strip().lower() in {"0", "false", "no"}


def _chat_model() -> Any | None:
    if _ollama_disabled():
        return None
    try:
        from langchain_ollama import ChatOllama
    except Exception as exc:
        logger.info("Ollama disabled: langchain_ollama unavailable: %s", exc)
        return None
    try:
        return ChatOllama(
            model=OLLAMA_MODEL,
            base_url=OLLAMA_BASE_URL,
            timeout=OLLAMA_TIMEOUT,
            temperature=0,
        )
    except Exception as exc:
        logger.warning("Ollama model setup failed: %s", exc)
        return None


def _json_from_text(text: str) -> dict[str, Any] | list[Any] | None:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = min([idx for idx in (text.find("{"), text.find("[")) if idx >= 0], default=-1)
    if start < 0:
        return None
    end_obj = text.rfind("}")
    end_arr = text.rfind("]")
    end = max(end_obj, end_arr)
    if end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def choose_sources_with_ollama(
    *,
    available_sources: list[str],
    fallback_source: str,
    fallback_label: int,
    counts: dict[int, int],
) -> SourceDecision | None:
    """Ask Ollama to choose a source strategy via tool binding."""
    model = _chat_model()
    if model is None:
        return None
    try:
        from langchain_core.tools import tool
    except Exception as exc:
        logger.info("Ollama source selection fallback: tool binding unavailable: %s", exc)
        return None

    @tool
    def select_source_strategy(
        source_type: str,
        selected_sources: list[str],
        expected_label: int,
        discovery_strategy: str,
        cti_queries: list[str],
    ) -> str:
        """Choose the next source strategy for the malware detection pipeline."""
        return "accepted"

    system = (
        "You are controlling a malware detection ingestion graph. "
        "Call select_source_strategy exactly once. "
        "Choose either malware-oriented sources or benign-oriented sources, not both. "
        "Use dynamic_cti only for malware hash discovery. "
        "If benign samples are underrepresented, prefer all benign providers. "
        "If malware is needed, prefer malwarebazaar and optionally dynamic_cti."
    )
    human = json.dumps(
        {
            "available_sources": available_sources,
            "fallback_source": fallback_source,
            "fallback_label": fallback_label,
            "sample_counts_by_label": counts,
            "default_cti_queries": [
                "recent Windows PE malware sha256 hashes github",
                "recent malware campaign sha256 PE hashes",
            ],
        }
    )
    try:
        response = model.bind_tools([select_source_strategy]).invoke(
            [("system", system), ("human", human)]
        )
    except Exception as exc:
        logger.info("Ollama source selection failed; using fallback: %s", exc)
        return None

    tool_calls = getattr(response, "tool_calls", None) or []
    if not tool_calls:
        return None
    args = dict(tool_calls[0].get("args") or {})
    try:
        decision = SourceDecision.model_validate(args)
    except ValidationError as exc:
        logger.info("Invalid Ollama source decision; using fallback: %s", exc)
        return None
    if decision.expected_label not in (0, 1):
        return None
    selected = [s for s in decision.selected_sources if s in available_sources]
    if not selected:
        return None
    source_type = decision.source_type if decision.source_type in selected else selected[0]
    return decision.model_copy(update={"selected_sources": selected, "source_type": source_type})


def generate_cti_queries(default_queries: list[str], limit: int = 3) -> list[str]:
    model = _chat_model()
    if model is None:
        return default_queries[:limit]
    prompt = (
        "Return a JSON array of concise web search queries for finding recent "
        "Windows PE malware SHA256 hashes from public CTI reports. "
        "Do not include URLs. Return JSON only."
    )
    try:
        response = model.invoke([("system", prompt), ("human", json.dumps(default_queries))])
        parsed = _json_from_text(str(getattr(response, "content", "")))
    except Exception as exc:
        logger.info("Ollama CTI query generation failed; using defaults: %s", exc)
        return default_queries[:limit]
    if not isinstance(parsed, list):
        return default_queries[:limit]
    queries = [str(item).strip() for item in parsed if str(item).strip()]
    return (queries or default_queries)[:limit]


def semantic_filter_hashes(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return accepted hash evidence. Fallback accepts malware-keyword contexts."""
    if not items:
        return []
    model = _chat_model()
    if model is None:
        return [item for item in items if _looks_malware_context(item.get("context", ""))]

    prompt = (
        "Filter candidate SHA256 hashes. Accept only hashes that the surrounding "
        "text indicates belong to malicious Windows PE executables, DLLs, loaders, "
        "droppers, ransomware, trojans, or malware samples. Reject IPs, images, "
        "documents, benign files, and unrelated indicators. Return JSON array with "
        "objects: sha256, accepted, reason."
    )
    try:
        response = model.invoke([("system", prompt), ("human", json.dumps(items[:25]))])
        parsed = _json_from_text(str(getattr(response, "content", "")))
    except Exception as exc:
        logger.info("Ollama semantic hash filtering failed; using fallback: %s", exc)
        return [item for item in items if _looks_malware_context(item.get("context", ""))]
    if not isinstance(parsed, list):
        return [item for item in items if _looks_malware_context(item.get("context", ""))]

    by_sha = {str(item.get("sha256", "")).lower(): item for item in items}
    accepted: list[dict[str, Any]] = []
    for row in parsed:
        if not isinstance(row, dict):
            continue
        sha = str(row.get("sha256", "")).lower()
        if row.get("accepted") is True and sha in by_sha:
            merged = dict(by_sha[sha])
            merged["semantic_reason"] = str(row.get("reason", "accepted by LLM"))
            accepted.append(merged)
    return accepted


def triage_pe_error(sha256: str, path: str, error: str, metadata: dict[str, Any]) -> str:
    """Return 'reject' or 'keep'. Fallback rejects parse failures."""
    model = _chat_model()
    if model is None:
        return "reject"
    prompt = (
        "A PE parser failed on a downloaded sample. Decide if this sample should be "
        "rejected from the current graph state as corrupted/non-PE. Return JSON only: "
        "{\"decision\":\"reject\"|\"keep\",\"reason\":\"...\"}."
    )
    payload = {"sha256": sha256, "path": path, "error": error, "metadata": metadata}
    try:
        response = model.invoke([("system", prompt), ("human", json.dumps(payload))])
        parsed = _json_from_text(str(getattr(response, "content", "")))
    except Exception as exc:
        logger.info("Ollama PE error triage failed; rejecting by default: %s", exc)
        return "reject"
    if isinstance(parsed, dict) and str(parsed.get("decision", "")).lower() == "keep":
        return "keep"
    return "reject"


def summarize_capa_findings(
    capa_results: dict[str, dict[str, Any]],
    feature_vectors: list[dict[str, Any]],
) -> str:
    avg_entropy = _average([float(f.get("avg_section_entropy", 0.0)) for f in feature_vectors])
    if not capa_results:
        return (
            "Drift detected. capa did not produce usable findings. "
            f"Batch size={len(feature_vectors)}, mean section entropy={avg_entropy:.4f}."
        )

    model = _chat_model()
    compact = {
        sha: _compact_capa_json(result)
        for sha, result in list(capa_results.items())[:5]
    }
    if model is None:
        rules = sorted(
            {
                rule
                for result in compact.values()
                for rule in result.get("rules", [])
            }
        )
        return (
            "Drift detected. capa identified capabilities: "
            f"{', '.join(rules[:12]) if rules else 'no named rules extracted'}. "
            f"Batch size={len(feature_vectors)}, mean section entropy={avg_entropy:.4f}."
        )

    prompt = (
        f"Write a concise malware drift explanation in {REPORT_LANGUAGE}. "
        "Use the capa capabilities and anomalous PE features. Focus on new malware "
        "capabilities and why retraining is justified. Avoid overstating certainty."
    )
    payload = {"capa": compact, "feature_vectors": feature_vectors[:10]}
    try:
        response = model.invoke([("system", prompt), ("human", json.dumps(payload))])
        content = str(getattr(response, "content", "")).strip()
        if content:
            return content
    except Exception as exc:
        logger.info("Ollama capa summarization failed; using fallback: %s", exc)
    return (
        "Drift detected. capa produced findings for "
        f"{len(capa_results)} sample(s). Batch size={len(feature_vectors)}, "
        f"mean section entropy={avg_entropy:.4f}."
    )


def _looks_malware_context(context: str) -> bool:
    text = context.lower()
    positive = ("malware", "ransomware", "trojan", "loader", "dropper", "backdoor", "stealer", "apt")
    negative = ("image", "png", "jpg", "jpeg", "pdf", "document", "benign")
    return any(word in text for word in positive) and not any(word in text for word in negative)


def _average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _compact_capa_json(result: dict[str, Any]) -> dict[str, Any]:
    rules_obj = result.get("rules") or {}
    if isinstance(rules_obj, dict):
        rules = list(rules_obj.keys())[:20]
    elif isinstance(rules_obj, list):
        rules = [str(item) for item in rules_obj[:20]]
    else:
        rules = []
    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    return {
        "rules": rules,
        "sample": meta.get("sample") or meta.get("analysis") or {},
    }

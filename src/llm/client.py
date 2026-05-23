"""Best-effort Ollama integration with deterministic fallbacks.

The pipeline must remain usable when Ollama is unavailable. Public helpers
therefore return None or conservative defaults instead of raising.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field

from src.config import (
    OLLAMA_BASE_URL,
    OLLAMA_ENABLED,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT,
    REPORT_LANGUAGE,
    ollama_drift_context_report_enabled,
    ollama_source_selection_enabled,
)
from src.llm.ollama_trace import invoke_chat
from src.log import PHASE_LLM, get_logger, phase_log, vlog

logger = get_logger(__name__)

_CODE_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*\n?(.*?)```", re.DOTALL)


class SourceDecision(BaseModel):
    source_type: str
    selected_sources: list[str] = Field(default_factory=list)
    expected_label: int
    discovery_strategy: str = ""


class SemanticHashVerdict(BaseModel):
    """Structured LLM output for a single hash evaluation."""

    sha256: str
    accepted: bool
    malware_family: str = ""
    is_technical_report: bool = False
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    reason: str = ""


def _ollama_disabled() -> bool:
    return not OLLAMA_ENABLED


def _chat_model() -> Any | None:
    if _ollama_disabled():
        vlog(logger, "info", "Ollama disabled via OLLAMA_ENABLED=False")
        return None
    try:
        from langchain_ollama import ChatOllama
    except Exception as exc:
        phase_log(logger, PHASE_LLM, "langchain_ollama unavailable: %s", exc, level="warning")
        return None
    try:
        return ChatOllama(
            model=OLLAMA_MODEL,
            base_url=OLLAMA_BASE_URL,
            timeout=OLLAMA_TIMEOUT,
            temperature=0,
        )
    except Exception as exc:
        phase_log(logger, PHASE_LLM, "model setup failed: %s", exc, level="warning")
        return None


def _fix_json_quirks(text: str) -> str:
    """Best-effort fixups for common Ollama JSON quirks."""
    text = re.sub(r",\s*([}\]])", r"\1", text)
    text = re.sub(r"\bTrue\b", "true", text)
    text = re.sub(r"\bFalse\b", "false", text)
    text = re.sub(r"\bNone\b", "null", text)
    return text


def _json_from_text(text: str | None) -> dict[str, Any] | list[Any] | None:
    """Extract JSON from LLM output, tolerating markdown fences and quirks."""
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fence_match = _CODE_FENCE_RE.search(text)
    if fence_match:
        inner = fence_match.group(1).strip()
        try:
            return json.loads(inner)
        except json.JSONDecodeError:
            text_to_parse = inner
    else:
        text_to_parse = text

    start = -1
    for i, ch in enumerate(text_to_parse):
        if ch in ("{", "["):
            start = i
            break
    if start < 0:
        return None

    closer = "}" if text_to_parse[start] == "{" else "]"
    end = text_to_parse.rfind(closer)
    if end <= start:
        return None

    candidate = text_to_parse[start : end + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    fixed = _fix_json_quirks(candidate)
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        return None


def choose_sources_with_ollama(
    *,
    available_sources: list[str],
    source_labels: dict[str, int],
    fallback_source: str,
    fallback_label: int,
    counts: dict[int, int],
) -> SourceDecision | None:
    """Ask Ollama to choose a source strategy via tool binding."""
    if not ollama_source_selection_enabled():
        return None
    model = _chat_model()
    if model is None:
        return None
    try:
        from langchain_core.tools import tool
        from src.tools.threat_intel_tools import build_intel_tools
    except Exception as exc:
        vlog(logger, "info","Ollama source selection fallback: tool binding unavailable: %s", exc)
        return None

    intel_tools = build_intel_tools()

    @tool
    def select_source_strategy(
        source_type: str,
        selected_sources: list[str] | None = None,
        discovery_strategy: str = "",
    ) -> str:
        """Choose the next source strategy.

        Args:
            source_type: One source name from available_sources.
            selected_sources: Optional source names with the same label.
            discovery_strategy: Optional short reason for the choice.
        """
        return "accepted"

    system = (
        "You are controlling a malware detection ingestion graph. "
        "Call select_source_strategy exactly once. "
        "The only required argument is source_type. "
        "Choose either malware-oriented sources or benign-oriented sources, not both. "
        "Use otx_pulse_cti for live OTX threat pulse malware discovery. "
        "When malware queue is shallow, call poll_intel_feeds then validate_and_queue_candidates. "
        "If benign samples are underrepresented, prefer all benign providers. "
        "If malware is needed, prefer malwarebazaar and active malware fallbacks. "
        "Do not provide expected_label; the program derives labels from the registry."
    )
    tools = [select_source_strategy, *intel_tools]
    human = json.dumps(
        {
            "available_sources": available_sources,
            "source_labels": source_labels,
            "fallback_source": fallback_source,
            "fallback_label": fallback_label,
            "sample_counts_by_label": counts,
        }
    )
    messages = [("system", system), ("human", human)]
    try:
        response = invoke_chat(
            model,
            messages,
            operation="source_selection",
            bind_tools=tools,
        )
    except Exception as exc:
        phase_log(logger, PHASE_LLM, "source_selection failed; using fallback: %s", exc, level="warning")
        return None

    tool_calls = getattr(response, "tool_calls", None) or []
    if not tool_calls:
        return None
    args = dict(tool_calls[0].get("args") or {})
    decision = _coerce_source_decision(args, available_sources, source_labels)
    if decision is None:
        vlog(logger, "info","Invalid Ollama source decision; using fallback: %s", args)
    return decision


def _coerce_source_decision(
    args: dict[str, Any],
    available_sources: list[str],
    source_labels: dict[str, int],
) -> SourceDecision | None:
    source_type = str(args.get("source_type") or "").strip()
    if source_type not in available_sources:
        return None

    expected_label = source_labels.get(source_type)
    if expected_label not in (0, 1):
        return None

    raw_selected = args.get("selected_sources") or [source_type]
    if isinstance(raw_selected, str):
        raw_selected = [raw_selected]
    if not isinstance(raw_selected, list):
        raw_selected = [source_type]

    selected: list[str] = []
    for item in raw_selected:
        name = str(item).strip()
        if name in available_sources and source_labels.get(name) == expected_label:
            selected.append(name)
    if source_type not in selected:
        selected.insert(0, source_type)

    return SourceDecision(
        source_type=source_type,
        selected_sources=selected,
        expected_label=expected_label,
        discovery_strategy=str(args.get("discovery_strategy") or "ollama"),
    )


def semantic_filter_hashes(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return accepted hash evidence with structured metadata.

    Each returned dict includes: semantic_reason, malware_family,
    is_technical_report, confidence_score.
    """
    if not items:
        return []
    model = _chat_model()
    if model is None:
        return _keyword_fallback(items)

    prompt = (
        "Filter candidate SHA256 hashes. For each hash, determine:\n"
        "1. accepted: true if the surrounding text indicates a malicious Windows PE "
        "(executables, DLLs, loaders, droppers, ransomware, trojans, stealers). "
        "Reject IPs, images, documents, benign files, unrelated indicators.\n"
        "2. malware_family: specific family name if identifiable (e.g. 'Emotet', "
        "'Cobalt Strike', 'QakBot'), or empty string if unknown.\n"
        "3. is_technical_report: true if the context comes from a structured CTI "
        "report, security advisory, or IOC feed rather than a tutorial, academic "
        "paper, blog opinion, or forum discussion.\n"
        "4. confidence_score: float 0.0-1.0 for how confident you are that this "
        "hash belongs to a real, downloadable malware PE sample.\n"
        "5. reason: brief explanation.\n\n"
        "Return JSON array only. Each object: "
        "{sha256, accepted, malware_family, is_technical_report, confidence_score, reason}"
    )
    messages = [("system", prompt), ("human", json.dumps(items[:25]))]
    phase_log(logger, PHASE_LLM, "semantic_filter: evaluating %d hash candidate(s)", min(len(items), 25))
    try:
        response = invoke_chat(model, messages, operation="semantic_filter")
        parsed = _json_from_text(str(getattr(response, "content", "")))
    except Exception as exc:
        phase_log(logger, PHASE_LLM, "semantic_filter failed; using keyword fallback: %s", exc, level="warning")
        return _keyword_fallback(items)
    if not isinstance(parsed, list):
        return _keyword_fallback(items)

    by_sha = {str(item.get("sha256", "")).lower(): item for item in items}
    accepted: list[dict[str, Any]] = []
    for row in parsed:
        if not isinstance(row, dict):
            continue
        try:
            verdict = SemanticHashVerdict(**row)
        except Exception:
            sha = str(row.get("sha256", "")).lower()
            if row.get("accepted") is True and sha in by_sha:
                merged = dict(by_sha[sha])
                merged["semantic_reason"] = str(row.get("reason", "accepted by LLM"))
                merged["malware_family"] = str(row.get("malware_family", ""))
                merged["is_technical_report"] = bool(row.get("is_technical_report", False))
                merged["confidence_score"] = float(row.get("confidence_score", 0.5))
                accepted.append(merged)
            continue
        sha = verdict.sha256.lower()
        if verdict.accepted and sha in by_sha:
            merged = dict(by_sha[sha])
            merged["semantic_reason"] = verdict.reason or "accepted by LLM"
            merged["malware_family"] = verdict.malware_family
            merged["is_technical_report"] = verdict.is_technical_report
            merged["confidence_score"] = verdict.confidence_score
            accepted.append(merged)
    return accepted


def _keyword_fallback(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic fallback when Ollama is unavailable."""
    results: list[dict[str, Any]] = []
    for item in items:
        if _looks_malware_context(item.get("context", "")):
            enriched = dict(item)
            enriched["semantic_reason"] = "keyword match fallback"
            enriched["malware_family"] = ""
            enriched["is_technical_report"] = False
            enriched["confidence_score"] = 0.5
            results.append(enriched)
    return results


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
    messages = [("system", prompt), ("human", json.dumps(payload))]
    try:
        response = invoke_chat(model, messages, operation="pe_error_triage")
        parsed = _json_from_text(str(getattr(response, "content", "")))
    except Exception as exc:
        phase_log(logger, PHASE_LLM, "pe_error_triage failed; rejecting by default: %s", exc, level="warning")
        return "reject"
    if isinstance(parsed, dict) and str(parsed.get("decision", "")).lower() == "keep":
        return "keep"
    return "reject"


def summarize_drift_context(
    drift_stats: dict[str, float],
    feature_vectors: list[dict[str, Any]],
    hash_metadata: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Produce a short drift narrative from statistics and static PE features."""
    if not ollama_drift_context_report_enabled():
        return ""

    avg_entropy = _average([float(f.get("avg_section_entropy", 0.0)) for f in feature_vectors])
    fallback = _drift_context_fallback(drift_stats, feature_vectors, avg_entropy)

    model = _chat_model()
    if model is None:
        return fallback

    prompt = (
        f"Write a concise malware concept-drift explanation in {REPORT_LANGUAGE}. "
        "Use the drift statistics and anomalous PE static features. Explain why the "
        "feature distribution shifted and why model retraining is justified. "
        "Avoid overstating certainty."
    )
    payload = {
        "drift_stats": drift_stats,
        "feature_summary": _compact_feature_summary(feature_vectors, hash_metadata),
    }
    messages = [("system", prompt), ("human", json.dumps(payload))]
    phase_log(
        logger,
        PHASE_LLM,
        "drift_summary: stats=%d feature_rows=%d",
        len(drift_stats),
        len(feature_vectors),
    )
    try:
        response = invoke_chat(model, messages, operation="drift_summary")
        content = str(getattr(response, "content", "")).strip()
        if content:
            return content
    except Exception as exc:
        phase_log(logger, PHASE_LLM, "drift_summary failed; using statistical fallback: %s", exc, level="warning")
    return fallback


def _drift_context_fallback(
    drift_stats: dict[str, float],
    feature_vectors: list[dict[str, Any]],
    avg_entropy: float,
) -> str:
    stats_bits = ", ".join(f"{k}={v:.4g}" for k, v in sorted(drift_stats.items()) if v is not None)
    return (
        "Concept drift detected. "
        f"Statistics: {stats_bits or 'n/a'}. "
        f"Batch size={len(feature_vectors)}, mean section entropy={avg_entropy:.4f}."
    )


def _compact_feature_summary(
    feature_vectors: list[dict[str, Any]],
    hash_metadata: dict[str, dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    keys = (
        "sha256",
        "avg_section_entropy",
        "num_sections",
        "has_debug",
        "has_imports",
        "has_exports",
        "has_authenticode",
    )
    out: list[dict[str, Any]] = []
    for fv in feature_vectors[:10]:
        sha = str(fv.get("sha256", ""))
        row = {k: fv[k] for k in keys if k in fv}
        if hash_metadata and sha in hash_metadata:
            meta = hash_metadata[sha]
            for mk in ("label", "malware_family", "signature", "provider"):
                if mk in meta:
                    row[mk] = meta[mk]
        out.append(row)
    return out


def _looks_malware_context(context: str) -> bool:
    text = context.lower()
    positive = ("malware", "ransomware", "trojan", "loader", "dropper", "backdoor", "stealer", "apt")
    negative = ("image", "png", "jpg", "jpeg", "pdf", "document", "benign")
    return any(word in text for word in positive) and not any(word in text for word in negative)


def _average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0

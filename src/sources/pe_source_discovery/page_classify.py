"""Heuristic + optional LLM classification of PE source pages."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from src.log import PHASE_DISCOVERY, get_logger, phase_log, vlog

logger = get_logger(__name__)

_DATASET_RE = re.compile(
    r"\b(dataset|malware sample|benign|goodware|PE files?|windows executables?|"
    r"download|api\.php|mb-api|malshare|github\.com)\b",
    re.I,
)
_MALWARE_RE = re.compile(
    r"\b(malware repository|virus samples?|malware only|malware exchange)\b",
    re.I,
)
_BENIGN_RE = re.compile(
    r"\b(benign executables?|goodware|malware[- ]free|normal \.net)\b",
    re.I,
)
_MIXED_RE = re.compile(r"\b(benign and malicious|whitelist|blacklist|labeled)\b", re.I)
_META_RE = re.compile(r"\b(awesome|curated list|index of datasets)\b", re.I)
_LINK_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_API_HOSTS = ("abuse.ch", "malshare.com", "bazaar.abuse.ch")


def classify_pe_source_page(url: str, text: str) -> dict[str, Any]:
    """Return classification dict for a fetched page."""
    snippet = (text or "")[:12000]
    lower = snippet.lower()
    host = (urlparse(url).hostname or "").lower()

    is_dataset = bool(_DATASET_RE.search(snippet)) or any(h in host for h in _API_HOSTS)
    if _META_RE.search(snippet) or "awesome-malware" in url.lower():
        source_type = "meta_index"
    elif _MIXED_RE.search(snippet):
        source_type = "mixed"
    elif _MALWARE_RE.search(snippet) or "malwarebazaar" in lower or "malshare" in lower:
        source_type = "malware_only"
    elif _BENIGN_RE.search(snippet) or "benign-net" in lower:
        source_type = "benign_only"
    elif is_dataset:
        source_type = "mixed"
    else:
        source_type = "none"

    access_type = "blog"
    automation_level = "none"
    content_format = "hashes_only"
    provider_name = ""

    if "api" in lower or host.endswith("abuse.ch") or "malshare.com" in host:
        access_type = "api"
        automation_level = "automatic_download"
        content_format = "raw_pe"
    elif "github.com" in host:
        access_type = "repo"
        if "benign" in lower:
            automation_level = "repo_clone"
            content_format = "raw_pe"
    elif ".zip" in lower or "onedrive" in lower:
        access_type = "static_dataset"
        automation_level = "manual_download"
        content_format = "raw_pe"

    if "malwarebazaar" in lower or "mb-api" in lower:
        provider_name = "malwarebazaar"
    elif "malshare" in lower:
        provider_name = "malshare"
    elif "benign-net" in lower or "bormaa" in lower:
        provider_name = "benign_net"
        source_type = "benign_only"

    candidate_links = _extract_links(url, snippet)[:20]
    label_quality = "high" if provider_name or source_type == "meta_index" else "medium"

    return {
        "is_dataset_page": is_dataset and source_type != "none",
        "likely_source_type": source_type,
        "access_type": access_type,
        "automation_level": automation_level,
        "content_format": content_format,
        "label_quality": label_quality,
        "provider_name": provider_name,
        "candidate_links": candidate_links,
        "reasons": f"host={host} type={source_type}",
    }


def _extract_links(base_url: str, text: str) -> list[str]:
    seen: set[str] = set()
    links: list[str] = []
    for match in _LINK_RE.findall(text):
        link = match.rstrip(").,;]")
        if link.startswith("//"):
            link = "https:" + link
        if not link.startswith("http"):
            continue
        if link not in seen:
            seen.add(link)
            links.append(link)
    return links


def refine_with_llm(url: str, text: str, heuristic: dict[str, Any]) -> dict[str, Any]:
    """Optional LLM refinement; falls back to heuristic on failure."""
    try:
        from src.llm.client import _chat_model, _json_from_text

        model = _chat_model()
        if model is None:
            return heuristic
        prompt = (
            "Classify this page as a PE malware/benign data source. "
            f"URL: {url}\nText excerpt:\n{text[:4000]}\n"
            "Return JSON only with: is_dataset_page (bool), likely_source_type "
            "(malware_only|benign_only|mixed|meta_index|none), access_type, "
            "automation_level, label_quality, provider_name."
        )
        from src.llm.ollama_trace import invoke_chat

        response = invoke_chat(
            model,
            [("system", prompt), ("human", text[:2000])],
            operation="pe_source_classify",
        )
        parsed = _json_from_text(str(getattr(response, "content", "")))
        if isinstance(parsed, dict):
            return {**heuristic, **{k: v for k, v in parsed.items() if v is not None}}
    except Exception as exc:
        vlog(logger, "debug", "LLM PE source classify skipped: %s", exc)
    return heuristic

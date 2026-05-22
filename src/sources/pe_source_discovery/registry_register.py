"""Register classified PE sources into PESourceStore."""

from __future__ import annotations

from typing import Any

from src.sources.pe_source_store import PESourceStore


def register_classification(
    store: PESourceStore,
    url: str,
    classification: dict[str, Any],
    *,
    discovery_query: str = "",
) -> bool:
    if not classification.get("is_dataset_page"):
        return False
    source_type = str(classification.get("likely_source_type") or "mixed")
    if source_type == "none":
        return False
    store.upsert(
        url,
        name=url.split("/")[-1][:120],
        source_type=source_type,
        access_type=str(classification.get("access_type") or "blog"),
        automation_level=str(classification.get("automation_level") or "none"),
        content_format=str(classification.get("content_format") or ""),
        label_quality=str(classification.get("label_quality") or "medium"),
        provider_name=str(classification.get("provider_name") or ""),
        status="active" if classification.get("provider_name") else "candidate",
        discovery_query=discovery_query,
        notes=str(classification.get("reasons") or ""),
    )
    provider = classification.get("provider_name")
    if provider:
        store.link_provider(url, str(provider))
    return True

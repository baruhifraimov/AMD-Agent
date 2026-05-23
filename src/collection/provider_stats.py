"""Helpers for accumulating provider yield metrics across one graph pass."""

from __future__ import annotations

from typing import Any

METRIC_KEYS = (
    "requested",
    "discovered",
    "fresh",
    "returned",
    "download_attempted",
    "downloaded",
    "duplicate",
    "non_pe",
    "valid_pe",
    "feature_extracted",
    "failed",
)


def _entry(metrics: dict[str, Any], provider: str, label: int | None) -> dict[str, Any]:
    stats = metrics.setdefault("provider_stats", {})
    key = f"{provider}:{label if label is not None else ''}"
    item = stats.setdefault(
        key,
        {
            "provider": provider,
            "label": label,
            **{name: 0 for name in METRIC_KEYS},
        },
    )
    return item


def bump_provider(
    metrics: dict[str, Any],
    provider: str,
    label: int | None,
    **counts: int,
) -> None:
    if not provider:
        return
    item = _entry(metrics, provider, label)
    for name, value in counts.items():
        if name in METRIC_KEYS:
            item[name] = int(item.get(name, 0)) + int(value or 0)


def merge_discovery_stats(metrics: dict[str, Any], discovery: list[dict[str, Any]]) -> None:
    for item in discovery:
        bump_provider(
            metrics,
            str(item.get("provider") or ""),
            int(item["label"]) if item.get("label") is not None else None,
            requested=int(item.get("requested", 0) or 0),
            discovered=int(item.get("discovered", 0) or 0),
            fresh=int(item.get("fresh", 0) or 0),
            returned=int(item.get("returned", 0) or 0),
            failed=1 if item.get("error") else 0,
        )


def record_provider_runs(
    tracker: Any,
    metrics: dict[str, Any],
    *,
    phase: str,
    stage: str = "pipeline",
) -> None:
    for item in (metrics.get("provider_stats") or {}).values():
        provider = str(item.get("provider") or "")
        if not provider:
            continue
        tracker.record_provider_run(
            provider=provider,
            label=item.get("label"),
            phase=phase,
            stage=stage,
            **{name: int(item.get(name, 0) or 0) for name in METRIC_KEYS},
        )

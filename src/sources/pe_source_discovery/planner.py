"""Discovery planner — search targets for PE source discovery."""

from __future__ import annotations

from typing import Any

DEFAULT_TARGETS: list[dict[str, Any]] = [
    {
        "channel": "seed",
        "queries": [
            "Windows PE malware dataset API",
            "benign Windows PE executables download github",
            "site:github.com PE malware dataset",
        ],
        "intent": "discover_new_sources",
    },
    {
        "channel": "seed",
        "queries": [
            "awesome malware benign datasets github",
            "malware sample resources PE",
        ],
        "intent": "meta_index",
    },
]


def plan_discovery_targets(
    *,
    registry_summary: str = "",
    need_malware: bool = True,
    need_benign: bool = False,
) -> list[dict[str, Any]]:
    """Return search targets from seeded defaults."""
    targets = [dict(t) for t in DEFAULT_TARGETS]
    if need_benign:
        targets.append(
            {
                "channel": "seed",
                "queries": [
                    "Benign-NET github PE executables",
                    "windows pe artifact library malware free",
                ],
                "intent": "benign_only",
            }
        )
    return targets

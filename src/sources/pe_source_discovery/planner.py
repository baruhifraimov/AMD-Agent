"""Discovery planner — search targets for PE source discovery."""

from __future__ import annotations

from typing import Any

DEFAULT_TARGETS: list[dict[str, Any]] = [
    {
        "channel": "web",
        "queries": [
            "Windows PE malware dataset API",
            "benign Windows PE executables download github",
            "site:github.com PE malware dataset",
        ],
        "intent": "discover_new_sources",
    },
    {
        "channel": "web",
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
    """Return search targets; extend with LLM when Ollama is available."""
    targets = [dict(t) for t in DEFAULT_TARGETS]
    if need_benign:
        targets.append(
            {
                "channel": "web",
                "queries": [
                    "Benign-NET github PE executables",
                    "windows pe artifact library malware free",
                ],
                "intent": "benign_only",
            }
        )
    default_queries = [
        "Windows PE malware dataset API github",
        "benign Windows PE executable dataset",
    ]
    try:
        from src.llm import generate_cti_queries

        extra = generate_cti_queries(default_queries, limit=5)
        if extra:
            targets.append(
                {"channel": "web", "queries": list(extra), "intent": "discover_new_sources"}
            )
    except Exception:
        pass
    return targets

"""Curated CTI source seeds for steady-state malware IOC discovery."""

from __future__ import annotations

from typing import Any

from src.intel.source_store import IntelSourceStore


CURATED_INTEL_SOURCES: tuple[dict[str, str], ...] = (
    {
        "name": "dfir-report",
        "url": "https://thedfirreport.com/feed/",
        "source_type": "rss",
    },
    {
        "name": "cisco-talos",
        "url": "https://blog.talosintelligence.com/rss/",
        "source_type": "rss",
    },
    {
        "name": "google-threat-intelligence",
        "url": "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
        "source_type": "rss",
    },
    {
        "name": "cisa-advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "source_type": "rss",
    },
    {
        "name": "unit42",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "source_type": "rss",
    },
    {
        "name": "securelist",
        "url": "https://securelist.com/feed/",
        "source_type": "rss",
    },
    {
        "name": "malwarebytes",
        "url": "https://www.malwarebytes.com/blog/feed",
        "source_type": "rss",
    },
)


def seed_curated_sources(store: IntelSourceStore) -> dict[str, Any]:
    """Ensure known CTI feeds exist in the dynamic source registry."""
    seeded = 0
    for source in CURATED_INTEL_SOURCES:
        sid = store.upsert_source(
            source["url"],
            source_type=source.get("source_type", "rss"),
            discovery_query=f"curated:{source['name']}",
            reset_zero_yield=False,
        )
        if sid is not None:
            seeded += 1
    return {
        "enabled": 1,
        "seeded": seeded,
        "configured": len(CURATED_INTEL_SOURCES),
        "total_enabled": store.count_enabled(),
    }

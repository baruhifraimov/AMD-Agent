"""Tests for curated CTI source seeding."""

from src.intel.seed_sources import CURATED_INTEL_SOURCES, seed_curated_sources
from src.intel.source_store import IntelSourceStore


def test_seed_curated_sources_upserts_known_feeds(tmp_paths):
    store = IntelSourceStore(tmp_paths["tracker"].db_path)

    stats = seed_curated_sources(store)

    assert stats["seeded"] == len(CURATED_INTEL_SOURCES)
    urls = {source["url"] for source in store.all_sources()}
    assert "https://thedfirreport.com/feed/" in urls
    assert "https://blog.talosintelligence.com/rss/" in urls

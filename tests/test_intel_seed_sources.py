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


def test_seed_curated_sources_does_not_reset_zero_yield(tmp_paths):
    store = IntelSourceStore(tmp_paths["tracker"].db_path)
    stats = seed_curated_sources(store)
    assert stats["seeded"] == len(CURATED_INTEL_SOURCES)

    source = next(s for s in store.all_sources() if s["url"] == "https://thedfirreport.com/feed/")
    sid = int(source["id"])
    store.schedule_next_poll(sid, queued_this_poll=0, bootstrap=False)

    seed_curated_sources(store)

    source = store.get_source(sid)
    assert source is not None
    assert int(source["zero_yield_polls"]) == 1

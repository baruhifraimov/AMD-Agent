"""Tests for intel source registry."""

from src.intel.source_store import IntelSourceStore


def test_upsert_and_list_due(tmp_paths):
    store = IntelSourceStore(tmp_paths["tracker"].db_path)
    sid = store.upsert_source("https://example.com/feed/", source_type="rss")
    assert sid is not None
    due = store.list_due_sources(limit=5)
    assert len(due) >= 1
    assert due[0]["url"] == "https://example.com/feed/"


def test_schedule_next_poll_disables_after_zero_yield(tmp_paths):
    store = IntelSourceStore(tmp_paths["tracker"].db_path)
    sid = store.upsert_source("https://example.org/rss", source_type="rss")
    assert sid is not None
    for _ in range(5):
        store.schedule_next_poll(sid, queued_this_poll=0, bootstrap=False)
    source = store.get_source(sid)
    assert source is not None
    assert int(source["enabled"]) == 0


def test_record_download_updates_yield(tmp_paths):
    store = IntelSourceStore(tmp_paths["tracker"].db_path)
    sid = store.upsert_source("https://example.net/feed", source_type="rss")
    store.record_queued(sid, count=2)
    store.record_download_outcome(sid, success=True)
    source = store.get_source(sid)
    assert source is not None
    assert float(source["yield_ratio"]) > 0

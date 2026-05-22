"""ThreatIntelCollector — discover, poll, validate, and queue malware IOCs."""

from __future__ import annotations

import logging
import re
from typing import Any

import src.db.tracker as db
from src.config import (
    CTI_SEED_SOURCES_ENABLED,
    MIN_TRAIN_MALWARE,
    PE_FETCH_LIMIT,
    THREATINGESTOR_BRIDGE_BATCH,
    THREATINGESTOR_ENABLED,
)
from src.intel.threatingestor_artifacts import (
    finalize_threatingestor_marks,
    poll_threatingestor_artifacts,
)
from src.intel.feed_discovery import discover_candidate_urls, is_low_signal_cti_url
from src.intel.rss import parse_feed_entries
from src.intel.seed_sources import seed_curated_sources
from src.intel.source_store import IntelSourceStore, get_intel_source_store
from src.llm import semantic_filter_hashes
from src.sources.base import SampleCandidate
from src.tools import malwarebazaar as mb
from src.tools.cti_search import extract_hash_contexts, extract_pe_urls, fetch_public_text
from src.tools.update import insert_pending_hash

logger = logging.getLogger(__name__)

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


class ThreatIntelCollector:
    """In-process CTI collector with ThreatIngestor artifact poll (Plan B)."""

    def __init__(
        self,
        *,
        tracker: db.MalwareTracker | None = None,
        source_store: IntelSourceStore | None = None,
    ) -> None:
        self.tracker = tracker or db.get_tracker()
        self.sources = source_store or get_intel_source_store(self.tracker.db_path)
        self.last_native_poll_stats: dict[str, Any] = {}

    def seed_curated_sources(self) -> dict[str, Any]:
        if not CTI_SEED_SOURCES_ENABLED:
            return {"enabled": 0, "seeded": 0}
        return seed_curated_sources(self.sources)

    def discover_sources(
        self,
        *,
        max_sources: int = 8,
        extra_queries: list[str] | None = None,
    ) -> dict[str, Any]:
        candidates = discover_candidate_urls(
            max_sources=max_sources,
            extra_queries=extra_queries,
        )
        added = 0
        for item in candidates:
            sid = self.sources.upsert_source(
                item["url"],
                source_type=item.get("source_type", "rss"),
                discovery_query=item.get("discovery_query", ""),
            )
            if sid is not None:
                added += 1
        return {
            "discovered": len(candidates),
            "upserted": added,
            "total_enabled": self.sources.count_enabled(),
        }

    def poll_due_feeds(
        self,
        *,
        max_sources: int = 5,
        max_candidates: int = 50,
    ) -> list[dict[str, Any]]:
        """Poll feeds due for refresh and return raw IOC candidates."""
        due = self.sources.list_due_sources(limit=max_sources)
        poll_stats: dict[str, Any] = {
            "sources_due": len(due),
            "sources_polled": 0,
            "entries": 0,
            "pages_fetched": 0,
            "raw_hashes": 0,
            "raw_pe_urls": 0,
            "returned": 0,
            "sources_disabled": 0,
            "source_urls": [],
        }
        raw: list[dict[str, Any]] = []
        seen_hashes: set[str] = set()
        seen_urls: set[str] = set()

        for source in due:
            source_id = int(source["id"])
            url = str(source["url"])
            source_type = str(source.get("source_type") or "rss")
            if is_low_signal_cti_url(url):
                logger.info("Disabling low-signal CTI source: %s", url)
                self.sources.disable_source(source_id)
                poll_stats["sources_disabled"] += 1
                continue
            self.sources.record_poll_start(source_id)
            poll_stats["sources_polled"] += 1
            poll_stats["source_urls"].append(url)

            entries: list[dict[str, Any]] = []
            if source_type == "rss":
                entries = parse_feed_entries(url, max_entries=15)
            elif source_type == "blog":
                text = fetch_public_text(url)
                if text:
                    entries = [{"title": "", "link": url, "body": text, "feed_url": url}]
            elif source_type == "github":
                entries = [{"title": "", "link": url, "body": url, "feed_url": url}]
            poll_stats["entries"] += len(entries)

            for entry in entries:
                combined = " ".join(
                    p for p in (entry.get("title", ""), entry.get("body", ""), entry.get("link", "")) if p
                )
                link = entry.get("link") or url
                if link and link != url:
                    page = fetch_public_text(link)
                    if page:
                        poll_stats["pages_fetched"] += 1
                    combined = f"{combined} {page}"

                for ctx in extract_hash_contexts(combined, url=link):
                    sha = str(ctx.get("sha256", "")).lower()
                    if sha in seen_hashes or len(sha) != 64:
                        continue
                    seen_hashes.add(sha)
                    self.sources.record_hashes_seen(source_id)
                    raw.append(
                        {
                            "sha256": sha,
                            "context": ctx.get("context", ""),
                            "article_url": link,
                            "feed_url": entry.get("feed_url") or url,
                            "title": entry.get("title", ""),
                            "source_id": source_id,
                            "discovery_source": "intel_rss",
                        }
                    )
                    poll_stats["raw_hashes"] += 1
                    if len(raw) >= max_candidates:
                        break

                for pe_url in extract_pe_urls(combined):
                    if pe_url in seen_urls:
                        continue
                    seen_urls.add(pe_url)
                    raw.append(
                        {
                            "fallback_url": pe_url,
                            "article_url": link,
                            "feed_url": entry.get("feed_url") or url,
                            "title": entry.get("title", ""),
                            "source_id": source_id,
                            "discovery_source": "intel_url",
                        }
                    )
                    poll_stats["raw_pe_urls"] += 1

                if len(raw) >= max_candidates:
                    break

        out = raw[:max_candidates]
        poll_stats["returned"] = len(out)
        self.last_native_poll_stats = poll_stats
        return out

    def poll_threatingestor_artifacts(
        self,
        batch_size: int | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Poll InQuest ThreatIngestor SQLite artifacts (sidecar producer)."""
        if not THREATINGESTOR_ENABLED:
            return [], {"disabled": 1}

        ti_source_id = self.sources.ensure_threatingestor_source()
        self.sources.record_poll_start(ti_source_id)

        raw, stats = poll_threatingestor_artifacts(
            batch_size=batch_size or THREATINGESTOR_BRIDGE_BATCH,
            source_id=ti_source_id or None,
        )
        for item in raw:
            self.sources.record_hashes_seen(ti_source_id)

        stats["source_id"] = ti_source_id
        return raw, stats

    def validate_and_queue(
        self,
        candidates: list[dict[str, Any]],
        *,
        use_semantic_filter: bool = True,
    ) -> dict[str, Any]:
        from src.collection.context import build_collection_context

        if build_collection_context(self.tracker).phase == "bootstrap":
            logger.info("validate_and_queue skipped: collection phase is bootstrap")
            return {
                "seen": len(candidates),
                "queued": 0,
                "rejected": 0,
                "existing": 0,
                "ignored": 0,
                "queued_hashes": [],
                "existing_hashes": [],
                "skipped": "bootstrap",
            }

        stats: dict[str, Any] = {
            "seen": 0,
            "hash_candidates": 0,
            "url_candidates": 0,
            "queued": 0,
            "rejected": 0,
            "existing": 0,
            "ignored": 0,
            "invalid_format": 0,
            "semantic_rejected": 0,
            "corrupted": 0,
            "not_pe": 0,
            "queued_hashes": [],
            "existing_hashes": [],
        }
        per_source_queued: dict[int, int] = {}
        ti_items = [c for c in candidates if c.get("_ti_artifact")]
        hash_items = [c for c in candidates if c.get("sha256")]
        url_items = [c for c in candidates if c.get("fallback_url") and not c.get("sha256")]
        stats["hash_candidates"] = len(hash_items)
        stats["url_candidates"] = len(url_items)

        if use_semantic_filter and hash_items:
            before_semantic = len(hash_items)
            filtered = semantic_filter_hashes(
                [
                    {
                        "sha256": item["sha256"],
                        "url": item.get("article_url", ""),
                        "context": item.get("context", ""),
                    }
                    for item in hash_items
                ]
            )
            accepted_shas = {str(i.get("sha256", "")).lower() for i in filtered}
            hash_items = [h for h in hash_items if h["sha256"] in accepted_shas]
            stats["semantic_rejected"] = max(0, before_semantic - len(hash_items))
            for item in filtered:
                sha = str(item.get("sha256", "")).lower()
                for raw in candidates:
                    if raw.get("sha256") == sha:
                        raw["semantic_reason"] = item.get("semantic_reason", "")

        for item in hash_items:
            stats["seen"] += 1
            sha = str(item.get("sha256", "")).lower()
            source_id = int(item.get("source_id") or 0)

            if not SHA256_RE.fullmatch(sha):
                stats["ignored"] += 1
                stats["invalid_format"] += 1
                continue
            if self.tracker.is_corrupted(sha):
                stats["rejected"] += 1
                stats["corrupted"] += 1
                continue
            if self.tracker.hash_exists(sha):
                stats["existing"] += 1
                stats["existing_hashes"].append(sha)
                continue
            try:
                if not self._is_pe_hash_cached(sha):
                    stats["rejected"] += 1
                    stats["not_pe"] += 1
                    continue
            except mb.MalwareBazaarUnavailable:
                logger.warning("MB circuit open; aborting validate_and_queue PE checks")
                break

            insert_pending_hash(self.tracker, sha, label=1)
            stats["queued"] += 1
            stats["queued_hashes"].append(sha)
            if source_id:
                self.sources.record_queued(source_id)
                per_source_queued[source_id] = per_source_queued.get(source_id, 0) + 1

        for item in url_items:
            stats["seen"] += 1
            url = str(item.get("fallback_url", ""))
            if self.tracker.hash_exists(url):
                stats["existing"] += 1
                continue
            insert_pending_hash(self.tracker, url, label=1)
            stats["queued"] += 1
            source_id = int(item.get("source_id") or 0)
            if source_id:
                self.sources.record_queued(source_id)
                per_source_queued[source_id] = per_source_queued.get(source_id, 0) + 1

        bootstrap = self._bootstrap_mode()
        polled_sources = {int(c.get("source_id") or 0) for c in candidates if c.get("source_id")}
        for sid in polled_sources:
            if sid:
                self.sources.schedule_next_poll(
                    sid,
                    queued_this_poll=per_source_queued.get(sid, 0),
                    bootstrap=bootstrap,
                )

        if ti_items and THREATINGESTOR_ENABLED:
            finalize_threatingestor_marks(
                ti_items,
                queued_hashes=set(stats["queued_hashes"]),
                already_known=set(stats["existing_hashes"]),
            )
            ti_sid = self.sources.ensure_threatingestor_source()
            if ti_sid:
                self.sources.schedule_next_poll(
                    ti_sid,
                    queued_this_poll=per_source_queued.get(ti_sid, 0),
                    bootstrap=bootstrap,
                )

        return stats

    def pending_to_candidates(self, limit: int | None = None) -> list[dict[str, Any]]:
        limit = limit or PE_FETCH_LIMIT
        pending = self.tracker.fetch_pending_hashes(limit=limit)
        candidates: list[dict[str, Any]] = []
        for row in pending:
            key = row["sha256"]
            if SHA256_RE.fullmatch(key):
                candidates.append(
                    SampleCandidate(
                        external_id=key,
                        provider="malwarebazaar",
                        expected_label=1,
                        download_ref={"sha256": key},
                        metadata={
                            "discovery_source": "intel_rss",
                            "first_seen": row.get("acquired_at") or "",
                        },
                    ).to_dict()
                )
            else:
                candidates.append(
                    SampleCandidate(
                        external_id=key,
                        provider="intel_direct",
                        expected_label=1,
                        download_ref={"fallback_url": key},
                        metadata={
                            "discovery_source": "intel_url",
                            "first_seen": row.get("acquired_at") or "",
                        },
                    ).to_dict()
                )
        return candidates

    def web_discover(self, limit: int, queries: list[str] | None = None) -> list[SampleCandidate]:
        """Web CTI discovery for DynamicCTIProvider delegation."""
        from src.config import CTI_PAGE_LIMIT
        from src.tools.cti_search import web_search

        curated_queries = [
            "site:thedfirreport.com sha256 malware",
            "site:blog.talosintelligence.com sha256 malware",
            "site:cloud.google.com/blog/topics/threat-intelligence sha256 malware",
            "site:github.com ioc sha256 malware windows pe",
        ]
        q = list(queries or [])
        if not q:
            from src.llm import generate_cti_queries

            q = generate_cti_queries(
                [
                    *curated_queries,
                    "recent Windows PE malware sha256 hashes github",
                ],
                limit=3,
            )
        for query in curated_queries:
            if query not in q:
                q.append(query)
            if len(q) >= 6:
                break
        evidence: list[dict[str, Any]] = []
        visited: set[str] = set()
        for query in q:
            for result in web_search(query):
                if len(visited) >= CTI_PAGE_LIMIT:
                    break
                url = result["url"]
                if url in visited:
                    continue
                if is_low_signal_cti_url(url):
                    logger.info("Skipping low-signal CTI page: %s", url)
                    continue
                visited.add(url)
                page = fetch_public_text(url)
                combined = " ".join(
                    p for p in (result.get("title", ""), result.get("snippet", ""), page) if p
                )
                evidence.extend(extract_hash_contexts(combined, url=url))

        candidates: list[SampleCandidate] = []
        seen: set[str] = set()
        for item in semantic_filter_hashes(evidence):
            if len(candidates) >= limit:
                break
            sha = str(item.get("sha256", "")).lower()
            if len(sha) != 64 or sha in seen:
                continue
            if (
                self.tracker.is_downloaded(sha)
                or self.tracker.is_corrupted(sha)
                or self.tracker.is_pending(sha)
            ):
                continue
            try:
                if not self._is_pe_hash_cached(sha):
                    continue
            except mb.MalwareBazaarUnavailable:
                logger.warning("MB circuit open; aborting web_discover PE checks")
                break
            seen.add(sha)
            candidates.append(
                SampleCandidate(
                    external_id=sha,
                    provider="dynamic_cti",
                    expected_label=1,
                    download_ref={"sha256": sha},
                    metadata={
                        "discovery_source": "dynamic_cti",
                        "origin_url": item.get("url", ""),
                        "semantic_evidence": item.get("context", "")[:1000],
                        "semantic_reason": item.get("semantic_reason", ""),
                    },
                )
            )
        logger.info("Dynamic CTI web_discover found %d candidate(s)", len(candidates))
        return candidates

    def record_download_outcome(self, metadata: dict[str, Any], *, success: bool) -> None:
        source_id = metadata.get("intel_source_id") or metadata.get("source_id")
        if source_id:
            try:
                self.sources.record_download_outcome(int(source_id), success=success)
            except (TypeError, ValueError):
                pass

    def run_ingest_pass(
        self,
        *,
        discover: bool = False,
        poll: bool = True,
        max_sources: int = 5,
        max_candidates: int = 50,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if CTI_SEED_SOURCES_ENABLED:
            result["seed_sources"] = self.seed_curated_sources()
        if discover or self.sources.count_enabled() == 0:
            result["discover"] = self.discover_sources(max_sources=max_sources)
        raw: list[dict[str, Any]] = []
        ti_raw, ti_stats = self.poll_threatingestor_artifacts()
        result["threatingestor"] = ti_stats
        raw.extend(ti_raw)
        if poll:
            native_raw = self.poll_due_feeds(
                max_sources=max_sources,
                max_candidates=max_candidates,
            )
            result["native_sources"] = self.last_native_poll_stats
            raw.extend(native_raw)
        result["poll_count"] = len(raw)
        result["validate"] = self.validate_and_queue(raw)
        result["sources_polled"] = [
            s["url"] for s in self.sources.list_due_sources(limit=max_sources)
        ]
        return result

    def _is_pe_hash_cached(self, sha: str) -> bool:
        if not mb.malwarebazaar_available():
            raise mb.MalwareBazaarUnavailable("MalwareBazaar circuit is open")
        try:
            return mb.is_pe_hash(sha)
        except mb.MalwareBazaarUnavailable:
            raise
        except Exception as exc:
            logger.info("MB is_pe_hash failed for %s: %s", sha, exc)
            return False

    def _bootstrap_mode(self) -> bool:
        counts = self.tracker.count_by_label()
        return int(counts.get(1, 0)) < MIN_TRAIN_MALWARE

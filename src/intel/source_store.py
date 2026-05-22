"""SQLite registry for dynamically discovered intel sources."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from src.config import DB_PATH, INTEL_MAX_POLL_INTERVAL, INTEL_MIN_POLL_INTERVAL, ensure_dirs
from src.intel.threatingestor_artifacts import THREATINGESTOR_SOURCE_URL

_SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    source_type TEXT NOT NULL DEFAULT 'rss',
    discovered_at TEXT NOT NULL,
    last_polled_at TEXT,
    next_poll_at TEXT NOT NULL,
    polls INTEGER NOT NULL DEFAULT 0,
    hashes_seen INTEGER NOT NULL DEFAULT 0,
    hashes_queued INTEGER NOT NULL DEFAULT 0,
    pe_download_ok INTEGER NOT NULL DEFAULT 0,
    pe_download_fail INTEGER NOT NULL DEFAULT 0,
    yield_ratio REAL NOT NULL DEFAULT 0.0,
    enabled INTEGER NOT NULL DEFAULT 1,
    discovery_query TEXT,
    zero_yield_polls INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_intel_sources_next_poll ON intel_sources(next_poll_at);
CREATE INDEX IF NOT EXISTS idx_intel_sources_enabled ON intel_sources(enabled);
"""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class IntelSourceStore:
    """Persistent store for CTI feed sources and yield metrics."""

    def __init__(self, db_path: Path | None = None) -> None:
        ensure_dirs()
        self.db_path = Path(db_path) if db_path else Path(DB_PATH)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def count_enabled(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM intel_sources WHERE enabled = 1"
            ).fetchone()
        return int(row["c"]) if row else 0

    def upsert_source(
        self,
        url: str,
        *,
        source_type: str = "rss",
        discovery_query: str = "",
        reset_zero_yield: bool = False,
    ) -> int | None:
        """Insert or refresh a discovered source. Returns source id."""
        now = _utc_now_iso()
        next_poll = now
        zero_yield_sql = ", zero_yield_polls = 0" if reset_zero_yield else ""
        with self._connect() as conn:
            conn.execute(
                f"""
                INSERT INTO intel_sources (url, source_type, discovered_at, next_poll_at, discovery_query)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    source_type = excluded.source_type,
                    discovery_query = COALESCE(excluded.discovery_query, intel_sources.discovery_query),
                    enabled = 1
                    {zero_yield_sql}
                """,
                (url.strip(), source_type, now, next_poll, discovery_query or None),
            )
            row = conn.execute("SELECT id FROM intel_sources WHERE url = ?", (url.strip(),)).fetchone()
        return int(row["id"]) if row else None

    def list_due_sources(self, limit: int = 10) -> list[dict[str, Any]]:
        now = _utc_now_iso()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM intel_sources
                WHERE enabled = 1
                  AND source_type != 'threatingestor'
                  AND next_poll_at <= ?
                ORDER BY yield_ratio DESC, next_poll_at ASC
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_source(self, source_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM intel_sources WHERE id = ?", (source_id,)
            ).fetchone()
        return dict(row) if row else None

    def record_poll_start(self, source_id: int) -> None:
        now = _utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE intel_sources
                SET last_polled_at = ?, polls = polls + 1
                WHERE id = ?
                """,
                (now, source_id),
            )

    def record_hashes_seen(self, source_id: int, count: int = 1) -> None:
        if count <= 0:
            return
        with self._connect() as conn:
            conn.execute(
                "UPDATE intel_sources SET hashes_seen = hashes_seen + ? WHERE id = ?",
                (count, source_id),
            )

    def record_queued(self, source_id: int, count: int = 1) -> None:
        if count <= 0:
            return
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE intel_sources
                SET hashes_queued = hashes_queued + ?,
                    zero_yield_polls = 0
                WHERE id = ?
                """,
                (count, source_id),
            )

    def record_download_outcome(self, source_id: int, *, success: bool) -> None:
        with self._connect() as conn:
            if success:
                conn.execute(
                    """
                    UPDATE intel_sources
                    SET pe_download_ok = pe_download_ok + 1
                    WHERE id = ?
                    """,
                    (source_id,),
                )
            else:
                conn.execute(
                    """
                    UPDATE intel_sources
                    SET pe_download_fail = pe_download_fail + 1
                    WHERE id = ?
                    """,
                    (source_id,),
                )
            row = conn.execute(
                "SELECT hashes_queued, pe_download_ok FROM intel_sources WHERE id = ?",
                (source_id,),
            ).fetchone()
            if row and int(row["hashes_queued"]) > 0:
                ratio = float(row["pe_download_ok"]) / max(1, int(row["hashes_queued"]))
                conn.execute(
                    "UPDATE intel_sources SET yield_ratio = ? WHERE id = ?",
                    (ratio, source_id),
                )

    def disable_source(self, source_id: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE intel_sources SET enabled = 0 WHERE id = ?",
                (source_id,),
            )

    def schedule_next_poll(
        self,
        source_id: int,
        *,
        queued_this_poll: int = 0,
        bootstrap: bool = False,
    ) -> None:
        source = self.get_source(source_id)
        if not source:
            return

        min_iv = INTEL_MIN_POLL_INTERVAL
        max_iv = INTEL_MAX_POLL_INTERVAL
        yield_ratio = float(source.get("yield_ratio") or 0.0)
        zero_polls = int(source.get("zero_yield_polls") or 0)

        if queued_this_poll == 0:
            zero_polls += 1
            with self._connect() as conn:
                conn.execute(
                    "UPDATE intel_sources SET zero_yield_polls = ? WHERE id = ?",
                    (zero_polls, source_id),
                )
            if zero_polls >= 5:
                with self._connect() as conn:
                    conn.execute(
                        "UPDATE intel_sources SET enabled = 0 WHERE id = ?",
                        (source_id,),
                    )
                return

        if bootstrap:
            base = min_iv
        elif yield_ratio > 0.3:
            base = min_iv
        elif yield_ratio > 0.0:
            base = min(max_iv // 4, 600)
        else:
            base = max_iv // 2

        if yield_ratio > 0.1:
            interval = max(min_iv, int(base / max(yield_ratio, 0.1)))
        else:
            interval = base
        interval = max(min_iv, min(max_iv, interval))

        next_at = datetime.now(timezone.utc) + timedelta(seconds=interval)
        with self._connect() as conn:
            conn.execute(
                "UPDATE intel_sources SET next_poll_at = ? WHERE id = ?",
                (next_at.replace(microsecond=0).isoformat(), source_id),
            )

    def all_sources(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM intel_sources ORDER BY yield_ratio DESC, url ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def ensure_threatingestor_source(self) -> int:
        """Virtual registry row for ThreatIngestor artifact yield tracking."""
        sid = self.upsert_source(
            THREATINGESTOR_SOURCE_URL,
            source_type="threatingestor",
            discovery_query="InQuest ThreatIngestor SQLite artifacts",
        )
        return int(sid) if sid is not None else 0


def get_intel_source_store(db_path: Path | None = None) -> IntelSourceStore:
    return IntelSourceStore(db_path)

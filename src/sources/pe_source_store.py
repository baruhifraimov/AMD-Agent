"""SQLite registry for discovered PE dataset/API sources."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from src.config import DB_PATH, ensure_dirs

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pe_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    name TEXT,
    source_type TEXT NOT NULL,
    access_type TEXT NOT NULL,
    automation_level TEXT NOT NULL,
    content_format TEXT,
    label_quality TEXT,
    provider_name TEXT,
    score REAL NOT NULL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'candidate',
    discovered_at TEXT NOT NULL,
    last_checked_at TEXT,
    discovery_query TEXT,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_pe_sources_status ON pe_sources(status);
CREATE INDEX IF NOT EXISTS idx_pe_sources_type ON pe_sources(source_type);
"""

_SEED_SOURCES: list[dict[str, str]] = [
    {
        "url": "https://github.com/0xh3xa/awesome-malware-benign-datasets",
        "name": "Awesome Malware Benign Datasets",
        "source_type": "meta_index",
        "access_type": "repo",
        "automation_level": "none",
        "content_format": "hashes_only",
        "label_quality": "high",
        "provider_name": "",
        "status": "active",
    },
    {
        "url": "https://bazaar.abuse.ch/api/",
        "name": "MalwareBazaar API",
        "source_type": "malware_only",
        "access_type": "api",
        "automation_level": "automatic_download",
        "content_format": "raw_pe",
        "label_quality": "high",
        "provider_name": "malwarebazaar",
        "status": "active",
    },
    {
        "url": "https://malshare.com/api.php",
        "name": "MalShare API",
        "source_type": "malware_only",
        "access_type": "api",
        "automation_level": "automatic_download",
        "content_format": "raw_pe",
        "label_quality": "medium",
        "provider_name": "malshare",
        "status": "active",
    },
]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class PESourceStore:
    """Persistent registry of PE file sources (datasets, APIs, repos)."""

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

    def count_active(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM pe_sources WHERE status = 'active'"
            ).fetchone()
        return int(row["c"]) if row else 0

    def upsert(
        self,
        url: str,
        *,
        name: str = "",
        source_type: str = "mixed",
        access_type: str = "blog",
        automation_level: str = "none",
        content_format: str = "",
        label_quality: str = "medium",
        provider_name: str = "",
        score: float | None = None,
        status: str = "candidate",
        discovery_query: str = "",
        notes: str = "",
    ) -> int | None:
        now = _utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO pe_sources (
                    url, name, source_type, access_type, automation_level,
                    content_format, label_quality, provider_name, score, status,
                    discovered_at, last_checked_at, discovery_query, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    name = COALESCE(NULLIF(excluded.name, ''), pe_sources.name),
                    source_type = excluded.source_type,
                    access_type = excluded.access_type,
                    automation_level = excluded.automation_level,
                    content_format = COALESCE(NULLIF(excluded.content_format, ''), pe_sources.content_format),
                    label_quality = COALESCE(NULLIF(excluded.label_quality, ''), pe_sources.label_quality),
                    provider_name = COALESCE(NULLIF(excluded.provider_name, ''), pe_sources.provider_name),
                    score = COALESCE(excluded.score, pe_sources.score),
                    status = excluded.status,
                    last_checked_at = excluded.last_checked_at,
                    discovery_query = COALESCE(NULLIF(excluded.discovery_query, ''), pe_sources.discovery_query),
                    notes = COALESCE(NULLIF(excluded.notes, ''), pe_sources.notes)
                """,
                (
                    url.strip(),
                    name,
                    source_type,
                    access_type,
                    automation_level,
                    content_format,
                    label_quality,
                    provider_name,
                    score if score is not None else 0.0,
                    status,
                    now,
                    now,
                    discovery_query or None,
                    notes or None,
                ),
            )
            row = conn.execute("SELECT id FROM pe_sources WHERE url = ?", (url.strip(),)).fetchone()
        return int(row["id"]) if row else None

    def list_active_by_type(self, source_type: str, *, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM pe_sources
                WHERE status = 'active' AND source_type = ?
                ORDER BY score DESC
                LIMIT ?
                """,
                (source_type, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def bump_score(self, url: str, delta: float) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE pe_sources SET score = score + ?, last_checked_at = ? WHERE url = ?",
                (delta, _utc_now_iso(), url.strip()),
            )

    def link_provider(self, url: str, provider_name: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE pe_sources
                SET provider_name = ?, status = 'active', last_checked_at = ?
                WHERE url = ?
                """,
                (provider_name, _utc_now_iso(), url.strip()),
            )

    def seed_defaults(self) -> int:
        count = 0
        for row in _SEED_SOURCES:
            if self.upsert(**row):
                count += 1
        return count

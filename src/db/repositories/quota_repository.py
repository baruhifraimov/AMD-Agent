"""MalwareBazaar API quota and PE verdict cache."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from src import config
from src.db.database import DatabaseManager
from src.db.row_utils import utc_now_iso, utc_today


class QuotaRepository:
    def __init__(self, db: DatabaseManager) -> None:
        self._db = db

    def get_mb_pe_verdict(self, sha256: str) -> bool | None:
        """Return cached PE verdict, or None on miss or expired entry."""
        key = sha256.lower()
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT is_pe, cached_at FROM mb_hash_cache WHERE sha256 = ?",
                (key,),
            ).fetchone()
        if not row:
            return None
        cached_at = row["cached_at"]
        try:
            cached_dt = datetime.strptime(cached_at, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return None
        age_days = (datetime.now(timezone.utc) - cached_dt).total_seconds() / 86400
        if age_days > config.MB_INFO_CACHE_TTL_DAYS:
            return None
        return bool(row["is_pe"])
    def mb_download_quota_available(self, *, limit: int | None = None) -> bool:
        """Return True if another get_file download is allowed today."""
        cap = limit if limit is not None else config.MB_DAILY_DOWNLOAD_LIMIT
        day = utc_today()
        with self._db.connect() as conn:
            count = self._mb_download_count(conn, day)
        return count < cap
    def record_mb_download(self) -> bool:
        """Increment daily get_file counter after a successful download."""
        cap = config.MB_DAILY_DOWNLOAD_LIMIT
        day = utc_today()
        with self._db.connect() as conn:
            self._mb_download_count(conn, day)
            conn.execute(
                """
                UPDATE mb_api_usage
                SET get_file_count = get_file_count + 1
                WHERE usage_date = ? AND get_file_count < ?
                """,
                (day, cap),
            )
            updated = conn.execute("SELECT changes()").fetchone()
        return bool(updated and int(updated[0]) > 0)
    def set_mb_pe_verdict(
        self,
        sha256: str,
        is_pe: bool,
        *,
        query_status: str = "ok",
    ) -> None:
        key = sha256.lower()
        now = utc_now_iso()
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT INTO mb_hash_cache (sha256, is_pe, cached_at, query_status)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    is_pe = excluded.is_pe,
                    cached_at = excluded.cached_at,
                    query_status = excluded.query_status
                """,
                (key, int(is_pe), now, query_status),
            )
    def _mb_download_count(self, conn: sqlite3.Connection, day: str) -> int:
        conn.execute(
            """
            INSERT INTO mb_api_usage (usage_date, get_file_count)
            VALUES (?, 0)
            ON CONFLICT(usage_date) DO NOTHING
            """,
            (day,),
        )
        row = conn.execute(
            "SELECT get_file_count FROM mb_api_usage WHERE usage_date = ?",
            (day,),
        ).fetchone()
        return int(row["get_file_count"]) if row else 0

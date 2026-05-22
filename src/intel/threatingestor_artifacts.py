"""Poll ThreatIngestor SQLite hash artifacts for in-process validation (Plan B)."""

from __future__ import annotations

import logging
import re
import sqlite3
from pathlib import Path
from typing import Any

from src.config import THREATINGESTOR_ARTIFACT_DB, THREATINGESTOR_BRIDGE_BATCH, ensure_dirs

logger = logging.getLogger(__name__)

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
STATE_QUEUED = "amd-agent-queued"
STATE_IGNORED = "amd-agent-ignored"

THREATINGESTOR_SOURCE_URL = "threatingestor://artifacts"


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def mark_artifact_state(conn: sqlite3.Connection, artifact: str, state: str) -> None:
    conn.execute("UPDATE hash SET state = ? WHERE artifact = ?", (state, artifact))


def fetch_unprocessed_rows(
    conn: sqlite3.Connection,
    *,
    limit: int,
) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    return conn.execute(
        """
        SELECT artifact, reference_link, reference_text, created_date
        FROM hash
        WHERE state IS NULL OR state = ''
        ORDER BY created_date ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def poll_threatingestor_artifacts(
    *,
    artifact_db: Path | None = None,
    batch_size: int | None = None,
    source_id: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Read unprocessed TI hash rows and return normalized IOC candidates.

    Does not write to malware_tracker.db; caller runs validate_and_queue then
    finalize_threatingestor_marks.
    """
    ensure_dirs()
    artifact_db = artifact_db or THREATINGESTOR_ARTIFACT_DB
    batch_size = batch_size or THREATINGESTOR_BRIDGE_BATCH
    stats: dict[str, int] = {
        "seen": 0,
        "candidates": 0,
        "ignored_format": 0,
        "missing_db": 0,
        "missing_table": 0,
    }
    candidates: list[dict[str, Any]] = []

    if not artifact_db.exists():
        stats["missing_db"] = 1
        return candidates, stats

    conn = sqlite3.connect(artifact_db)
    try:
        if not _table_exists(conn, "hash"):
            stats["missing_table"] = 1
            return candidates, stats

        rows = fetch_unprocessed_rows(conn, limit=batch_size)
        for row in rows:
            stats["seen"] += 1
            artifact = str(row["artifact"] or "").strip()
            sha = artifact.lower()
            if not SHA256_RE.fullmatch(sha):
                stats["ignored_format"] += 1
                mark_artifact_state(conn, artifact, STATE_IGNORED)
                continue

            candidates.append(
                {
                    "sha256": sha,
                    "context": str(row["reference_text"] or "")[:2000],
                    "article_url": str(row["reference_link"] or ""),
                    "title": "",
                    "feed_url": THREATINGESTOR_SOURCE_URL,
                    "source_id": source_id,
                    "discovery_source": "intel_threatingestor",
                    "_ti_artifact": artifact,
                }
            )
            stats["candidates"] += 1

        conn.commit()
    finally:
        conn.close()

    return candidates, stats


def finalize_threatingestor_marks(
    ti_candidates: list[dict[str, Any]],
    *,
    queued_hashes: set[str],
    already_known: set[str] | None = None,
    artifact_db: Path | None = None,
) -> None:
    """Mark TI artifact rows after validate_and_queue completes."""
    if not ti_candidates:
        return
    artifact_db = artifact_db or THREATINGESTOR_ARTIFACT_DB
    if not artifact_db.exists():
        return

    known = already_known or set()
    conn = sqlite3.connect(artifact_db)
    try:
        for item in ti_candidates:
            artifact = item.get("_ti_artifact")
            if not artifact:
                continue
            sha = str(item.get("sha256", "")).lower()
            if sha in queued_hashes or sha in known:
                mark_artifact_state(conn, artifact, STATE_QUEUED)
            else:
                mark_artifact_state(conn, artifact, STATE_IGNORED)
        conn.commit()
    finally:
        conn.close()


def artifact_state_counts(*, artifact_db: Path | None = None) -> dict[str, int]:
    """Return ThreatIngestor hash artifact counters grouped by state."""
    ensure_dirs()
    artifact_db = artifact_db or THREATINGESTOR_ARTIFACT_DB
    stats = {
        "db_exists": 0,
        "table_exists": 0,
        "total": 0,
        "sha256": 0,
        "unprocessed": 0,
        "queued": 0,
        "ignored": 0,
        "other_state": 0,
    }
    if not artifact_db.exists():
        return stats
    stats["db_exists"] = 1

    conn = sqlite3.connect(artifact_db)
    conn.row_factory = sqlite3.Row
    try:
        if not _table_exists(conn, "hash"):
            return stats
        stats["table_exists"] = 1
        rows = conn.execute("SELECT artifact, state FROM hash").fetchall()
    finally:
        conn.close()

    stats["total"] = len(rows)
    for row in rows:
        artifact = str(row["artifact"] or "").strip()
        state = str(row["state"] or "").strip()
        if SHA256_RE.fullmatch(artifact):
            stats["sha256"] += 1
        if not state:
            stats["unprocessed"] += 1
        elif state == STATE_QUEUED:
            stats["queued"] += 1
        elif state == STATE_IGNORED:
            stats["ignored"] += 1
        else:
            stats["other_state"] += 1
    return stats


def reset_ignored_sha256_artifacts(*, artifact_db: Path | None = None) -> int:
    """Reset ignored SHA256 artifacts so they can be revalidated after auth fixes."""
    ensure_dirs()
    artifact_db = artifact_db or THREATINGESTOR_ARTIFACT_DB
    if not artifact_db.exists():
        return 0

    conn = sqlite3.connect(artifact_db)
    try:
        if not _table_exists(conn, "hash"):
            return 0
        rows = conn.execute(
            "SELECT artifact FROM hash WHERE state = ?",
            (STATE_IGNORED,),
        ).fetchall()
        shas = []
        for row in rows:
            artifact = str(row[0] or "").strip()
            if SHA256_RE.fullmatch(artifact):
                shas.append(artifact)
        for sha in shas:
            conn.execute("UPDATE hash SET state = NULL WHERE artifact = ?", (sha,))
        conn.commit()
        return len(shas)
    finally:
        conn.close()

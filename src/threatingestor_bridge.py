"""Import ThreatIngestor hash artifacts into AMD-Agent's pending queue."""

from __future__ import annotations

import argparse
import logging
import re
import sqlite3
import time
from pathlib import Path

import src.db.tracker as db
from src.config import (
    THREATINGESTOR_ARTIFACT_DB,
    THREATINGESTOR_BRIDGE_BATCH,
    THREATINGESTOR_BRIDGE_INTERVAL,
    ensure_dirs,
)

logger = logging.getLogger(__name__)

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
STATE_QUEUED = "amd-agent-queued"
STATE_IGNORED = "amd-agent-ignored"


def bridge_once(
    *,
    artifact_db: Path | None = None,
    tracker: db.MalwareTracker | None = None,
    batch_size: int | None = None,
) -> dict[str, int]:
    """Move new SHA256 artifacts into samples as pending malware hashes."""
    ensure_dirs()
    artifact_db = artifact_db or THREATINGESTOR_ARTIFACT_DB
    tracker = tracker or db.get_tracker()
    batch_size = batch_size or THREATINGESTOR_BRIDGE_BATCH
    stats = {
        "seen": 0,
        "queued": 0,
        "existing": 0,
        "ignored": 0,
        "missing_db": 0,
        "missing_table": 0,
    }

    if not artifact_db.exists():
        stats["missing_db"] = 1
        return stats

    conn = sqlite3.connect(artifact_db)
    try:
        conn.row_factory = sqlite3.Row
        if not _table_exists(conn, "hash"):
            stats["missing_table"] = 1
            return stats

        rows = conn.execute(
            """
            SELECT artifact, created_date
            FROM hash
            WHERE state IS NULL OR state = ''
            ORDER BY created_date ASC
            LIMIT ?
            """,
            (batch_size,),
        ).fetchall()

        for row in rows:
            stats["seen"] += 1
            artifact = str(row["artifact"] or "").strip()
            sha = artifact.lower()
            if not SHA256_RE.fullmatch(sha):
                _mark_artifact_state(conn, artifact, STATE_IGNORED)
                stats["ignored"] += 1
                continue

            if tracker.hash_exists(sha):
                stats["existing"] += 1
            else:
                tracker.insert_pending_hash(sha, row["created_date"], label=1)
                stats["queued"] += 1

            _mark_artifact_state(conn, artifact, STATE_QUEUED)

        conn.commit()
    finally:
        conn.close()

    return stats


def run_daemon(interval_seconds: int = THREATINGESTOR_BRIDGE_INTERVAL) -> None:
    """Continuously bridge ThreatIngestor artifacts into AMD-Agent SQLite."""
    while True:
        try:
            stats = bridge_once()
            if stats["seen"] or stats["missing_table"]:
                logger.info("ThreatIngestor bridge stats: %s", stats)
        except Exception:
            logger.exception("ThreatIngestor bridge pass failed")
        time.sleep(interval_seconds)


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _mark_artifact_state(conn: sqlite3.Connection, artifact: str, state: str) -> None:
    conn.execute("UPDATE hash SET state = ? WHERE artifact = ?", (state, artifact))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Bridge ThreatIngestor hashes to AMD-Agent")
    parser.add_argument("--daemon", action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=int, default=THREATINGESTOR_BRIDGE_INTERVAL)
    parser.add_argument("--batch-size", type=int, default=THREATINGESTOR_BRIDGE_BATCH)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if args.daemon:
        run_daemon(args.interval)
    else:
        stats = bridge_once(batch_size=args.batch_size)
        logger.info("ThreatIngestor bridge stats: %s", stats)


if __name__ == "__main__":
    main()

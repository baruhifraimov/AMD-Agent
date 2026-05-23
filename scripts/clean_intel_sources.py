#!/usr/bin/env python3
"""Disable low-signal intel_sources rows from the tracker SQLite DB."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Any

from src.config import DB_PATH, ensure_dirs
from src.intel.feed_discovery import is_low_signal_cti_url, is_precise_intel_source_url


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _disable_reason(row: dict[str, Any]) -> str:
    url = str(row.get("url") or "")
    source_type = str(row.get("source_type") or "rss")
    if source_type != "rss":
        return f"non-rss:{source_type}"
    if is_low_signal_cti_url(url):
        return "low-signal-url"
    if not is_precise_intel_source_url(url):
        return "not-precise-feed"
    return ""


def clean_intel_sources(db_path: Path, *, apply: bool = False) -> list[dict[str, Any]]:
    ensure_dirs()
    if not db_path.exists():
        raise FileNotFoundError(db_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    disabled: list[dict[str, Any]] = []
    try:
        if not _table_exists(conn, "intel_sources"):
            return disabled
        rows = conn.execute(
            """
            SELECT id, url, source_type, enabled, polls, hashes_seen, hashes_queued
            FROM intel_sources
            WHERE enabled = 1
            ORDER BY id
            """
        ).fetchall()
        for row in rows:
            item = dict(row)
            reason = _disable_reason(item)
            if not reason:
                continue
            item["reason"] = reason
            disabled.append(item)
            if apply:
                conn.execute(
                    "UPDATE intel_sources SET enabled = 0 WHERE id = ?",
                    (int(item["id"]),),
                )
        if apply:
            conn.commit()
    finally:
        conn.close()
    return disabled


def main() -> None:
    parser = argparse.ArgumentParser(description="Clean low-signal intel_sources rows")
    parser.add_argument("--db", type=Path, default=DB_PATH)
    parser.add_argument("--apply", action="store_true", help="Actually disable rows")
    args = parser.parse_args()

    rows = clean_intel_sources(args.db, apply=args.apply)
    mode = "disabled" if args.apply else "would_disable"
    print(f"{mode}={len(rows)} db={args.db}")
    for row in rows:
        print(
            f"{row['id']}\t{row['reason']}\t{row['source_type']}\t"
            f"polls={row['polls']} hashes={row['hashes_seen']} queued={row['hashes_queued']}\t"
            f"{row['url']}"
        )


if __name__ == "__main__":
    main()

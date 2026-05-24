"""DatabaseManager schema initialization."""

import sqlite3
from pathlib import Path

from src.db.database import DatabaseManager


def test_database_manager_creates_tables_and_wal(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    DatabaseManager(db_path).ensure_initialized()
    conn = sqlite3.connect(db_path)
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    finally:
        conn.close()
    assert mode.lower() == "wal"
    assert "samples" in tables
    assert "mb_hash_cache" in tables
    assert "provider_runs" in tables

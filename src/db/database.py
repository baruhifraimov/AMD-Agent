"""SQLite connection lifecycle for MalwareTracker."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from src.config import ensure_dirs
from src.db.migrations import migrate_schema
from src.db.schema import SCHEMA


class DatabaseManager:
    """Owns DB path, connections, schema init, and migrations."""

    def __init__(self, db_path: Path) -> None:
        ensure_dirs()
        self.db_path = Path(db_path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def ensure_initialized(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute("PRAGMA journal_mode=WAL;")
            migrate_schema(conn)

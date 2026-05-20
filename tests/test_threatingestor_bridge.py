"""Tests for bridging ThreatIngestor artifacts into the AMD-Agent queue."""

import sqlite3
from contextlib import closing

from src.threatingestor_bridge import STATE_IGNORED, STATE_QUEUED, bridge_once


def _init_artifact_db(path):
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            """
            CREATE TABLE hash (
                artifact TEXT PRIMARY KEY,
                reference_link TEXT,
                reference_text TEXT,
                created_date TEXT,
                state TEXT
            )
            """
        )


def test_bridge_queues_sha256_artifacts(tmp_paths, tmp_path):
    artifact_db = tmp_path / "threatingestor_artifacts.db"
    _init_artifact_db(artifact_db)
    sha = "a" * 64
    with closing(sqlite3.connect(artifact_db)) as conn:
        conn.execute(
            "INSERT INTO hash (artifact, created_date, state) VALUES (?, ?, NULL)",
            (sha, "2026-05-20 12:00:00"),
        )

    stats = bridge_once(artifact_db=artifact_db, tracker=tmp_paths["tracker"])

    assert stats["queued"] == 1
    pending = tmp_paths["tracker"].fetch_pending_hashes()
    assert pending[0]["sha256"] == sha
    with closing(sqlite3.connect(artifact_db)) as conn:
        state = conn.execute("SELECT state FROM hash WHERE artifact = ?", (sha,)).fetchone()[0]
    assert state == STATE_QUEUED


def test_bridge_ignores_non_sha256_hashes(tmp_paths, tmp_path):
    artifact_db = tmp_path / "threatingestor_artifacts.db"
    _init_artifact_db(artifact_db)
    md5 = "b" * 32
    with closing(sqlite3.connect(artifact_db)) as conn:
        conn.execute(
            "INSERT INTO hash (artifact, created_date, state) VALUES (?, ?, NULL)",
            (md5, "2026-05-20 12:00:00"),
        )

    stats = bridge_once(artifact_db=artifact_db, tracker=tmp_paths["tracker"])

    assert stats["ignored"] == 1
    assert tmp_paths["tracker"].fetch_pending_hashes() == []
    with closing(sqlite3.connect(artifact_db)) as conn:
        state = conn.execute("SELECT state FROM hash WHERE artifact = ?", (md5,)).fetchone()[0]
    assert state == STATE_IGNORED

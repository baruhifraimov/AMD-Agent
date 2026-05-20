"""Tests for ThreatIngestor artifact polling (Plan B)."""

import sqlite3
from contextlib import closing

from src.intel.threatingestor_artifacts import (
    STATE_IGNORED,
    STATE_QUEUED,
    finalize_threatingestor_marks,
    poll_threatingestor_artifacts,
)


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


def test_poll_returns_normalized_candidates(tmp_path):
    artifact_db = tmp_path / "threatingestor_artifacts.db"
    _init_artifact_db(artifact_db)
    sha = "a" * 64
    with closing(sqlite3.connect(artifact_db)) as conn:
        conn.execute(
            "INSERT INTO hash (artifact, reference_link, reference_text, created_date) VALUES (?, ?, ?, ?)",
            (sha, "https://example.com/post", "malware PE trojan", "2026-05-20"),
        )

    raw, stats = poll_threatingestor_artifacts(artifact_db=artifact_db, source_id=99)

    assert stats["candidates"] == 1
    assert raw[0]["sha256"] == sha
    assert raw[0]["discovery_source"] == "intel_threatingestor"
    assert raw[0]["source_id"] == 99
    assert raw[0]["_ti_artifact"] == sha


def test_poll_ignores_invalid_hash_format(tmp_path):
    artifact_db = tmp_path / "threatingestor_artifacts.db"
    _init_artifact_db(artifact_db)
    md5 = "b" * 32
    with closing(sqlite3.connect(artifact_db)) as conn:
        conn.execute(
            "INSERT INTO hash (artifact, created_date) VALUES (?, ?)",
            (md5, "2026-05-20"),
        )

    raw, stats = poll_threatingestor_artifacts(artifact_db=artifact_db)

    assert raw == []
    assert stats["ignored_format"] == 1
    with closing(sqlite3.connect(artifact_db)) as conn:
        state = conn.execute("SELECT state FROM hash WHERE artifact = ?", (md5,)).fetchone()[0]
    assert state == STATE_IGNORED


def test_finalize_marks_queued_and_known(tmp_path):
    artifact_db = tmp_path / "threatingestor_artifacts.db"
    _init_artifact_db(artifact_db)
    sha_q = "c" * 64
    sha_k = "d" * 64
    with closing(sqlite3.connect(artifact_db)) as conn:
        conn.execute("INSERT INTO hash (artifact, created_date) VALUES (?, ?)", (sha_q, "t1"))
        conn.execute("INSERT INTO hash (artifact, created_date) VALUES (?, ?)", (sha_k, "t2"))

    ti_items = [
        {"sha256": sha_q, "_ti_artifact": sha_q},
        {"sha256": sha_k, "_ti_artifact": sha_k},
    ]
    finalize_threatingestor_marks(
        ti_items,
        queued_hashes={sha_q},
        already_known={sha_k},
        artifact_db=artifact_db,
    )

    with closing(sqlite3.connect(artifact_db)) as conn:
        s_q = conn.execute("SELECT state FROM hash WHERE artifact = ?", (sha_q,)).fetchone()[0]
        s_k = conn.execute("SELECT state FROM hash WHERE artifact = ?", (sha_k,)).fetchone()[0]
    assert s_q == STATE_QUEUED
    assert s_k == STATE_QUEUED

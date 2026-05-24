"""Incremental schema migrations for existing MalwareTracker databases."""

from __future__ import annotations

import sqlite3


def migrate_schema(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(samples)")}
    if "status" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN status TEXT")
    if "reject_reason" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN reject_reason TEXT")
    if "rejected_at" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN rejected_at TEXT")
    if "source_provider" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN source_provider TEXT")
    if "source_url" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN source_url TEXT")
    if "feature_version" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN feature_version TEXT")
    if "feature_dim" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN feature_dim INTEGER")
    if "ingested_at" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN ingested_at TEXT")
    if "source_first_seen" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN source_first_seen TEXT")
    if "malware_family" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN malware_family TEXT")
    if "task_id" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN task_id INTEGER")
    if "trained_at" not in columns:
        conn.execute("ALTER TABLE samples ADD COLUMN trained_at TEXT")
    conn.execute(
        """
        UPDATE samples
        SET status = CASE
            WHEN file_path IS NULL OR file_path = '' THEN 'pending'
            ELSE 'active'
        END
        WHERE status IS NULL OR status = ''
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_status ON samples(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_source_url ON samples(source_url)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_feature_version ON samples(feature_version)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_ingested ON samples(ingested_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_family ON samples(malware_family)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_task_id ON samples(task_id)")
    conn.execute(
        """
        UPDATE samples
        SET ingested_at = acquired_at
        WHERE ingested_at IS NULL OR ingested_at = ''
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sample_sources (
            source_url TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            source_provider TEXT,
            first_seen_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sample_sources_sha256 ON sample_sources(sha256)")
    conn.execute(
        """
        INSERT OR IGNORE INTO sample_sources
        (source_url, sha256, source_provider, first_seen_at)
        SELECT source_url, sha256, source_provider, acquired_at
        FROM samples
        WHERE source_url IS NOT NULL AND source_url != ''
        """
    )
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS provider_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            label INTEGER,
            phase TEXT,
            stage TEXT,
            requested INTEGER NOT NULL DEFAULT 0,
            discovered INTEGER NOT NULL DEFAULT 0,
            fresh INTEGER NOT NULL DEFAULT 0,
            returned INTEGER NOT NULL DEFAULT 0,
            download_attempted INTEGER NOT NULL DEFAULT 0,
            downloaded INTEGER NOT NULL DEFAULT 0,
            duplicate INTEGER NOT NULL DEFAULT 0,
            non_pe INTEGER NOT NULL DEFAULT 0,
            valid_pe INTEGER NOT NULL DEFAULT 0,
            feature_extracted INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_provider_runs_provider_label
            ON provider_runs(provider, label, created_at);
        CREATE TABLE IF NOT EXISTS candidates (
            candidate_key TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            label INTEGER,
            external_id TEXT,
            sha256 TEXT,
            source_url TEXT,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            last_error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_candidates_provider ON candidates(provider, label, status);
        CREATE INDEX IF NOT EXISTS idx_candidates_sha256 ON candidates(sha256);
        CREATE TABLE IF NOT EXISTS collection_counters (
            name TEXT PRIMARY KEY,
            value INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS task_log (
            task_id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            sample_count INTEGER NOT NULL DEFAULT 0,
            trigger TEXT,
            replay_budget_used INTEGER,
            model_version TEXT
        );
        CREATE TABLE IF NOT EXISTS family_counts (
            malware_family TEXT PRIMARY KEY,
            sample_count INTEGER NOT NULL DEFAULT 0,
            last_seen_at TEXT
        );
        """
    )

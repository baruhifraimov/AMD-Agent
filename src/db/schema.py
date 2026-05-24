"""SQLite DDL for MalwareTracker."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sha256 TEXT PRIMARY KEY,
    file_path TEXT,
    acquired_at TEXT NOT NULL,
    features_json TEXT,
    label INTEGER,
    prediction REAL,
    anomaly_score REAL,
    status TEXT NOT NULL DEFAULT 'active',
    reject_reason TEXT,
    rejected_at TEXT,
    source_provider TEXT,
    source_url TEXT,
    feature_version TEXT,
    feature_dim INTEGER,
    ingested_at TEXT,
    source_first_seen TEXT,
    malware_family TEXT,
    task_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_samples_acquired ON samples(acquired_at);
CREATE INDEX IF NOT EXISTS idx_samples_ingested ON samples(ingested_at);
CREATE INDEX IF NOT EXISTS idx_samples_status ON samples(status);
CREATE INDEX IF NOT EXISTS idx_samples_source_url ON samples(source_url);
CREATE INDEX IF NOT EXISTS idx_samples_feature_version ON samples(feature_version);
CREATE INDEX IF NOT EXISTS idx_samples_family ON samples(malware_family);
CREATE INDEX IF NOT EXISTS idx_samples_task_id ON samples(task_id);
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
CREATE TABLE IF NOT EXISTS mb_hash_cache (
    sha256 TEXT PRIMARY KEY,
    is_pe INTEGER NOT NULL,
    cached_at TEXT NOT NULL,
    query_status TEXT
);
CREATE TABLE IF NOT EXISTS mb_api_usage (
    usage_date TEXT PRIMARY KEY,
    get_file_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sample_sources (
    source_url TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    source_provider TEXT,
    first_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sample_sources_sha256 ON sample_sources(sha256);
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
CREATE INDEX IF NOT EXISTS idx_provider_runs_provider_label ON provider_runs(provider, label, created_at);
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
"""

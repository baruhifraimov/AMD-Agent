"""Quiet ThreatIngestor sidecar summaries."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from src.config import THREATINGESTOR_ARTIFACT_DB, ensure_dirs
from src.intel.threatingestor_artifacts import SHA256_RE, STATE_IGNORED, STATE_QUEUED

NEW_ARTIFACTS_RE = re.compile(r"New artifacts:\s*(\{.*\})")


def artifact_snapshot(artifact_db: Path | None = None) -> dict[str, Any]:
    """Return compact artifact DB counters without mutating ThreatIngestor state."""
    ensure_dirs()
    artifact_db = artifact_db or THREATINGESTOR_ARTIFACT_DB
    stats: dict[str, Any] = {
        "db_exists": artifact_db.exists(),
        "table_exists": False,
        "total": 0,
        "sha256": 0,
        "unprocessed": 0,
        "queued": 0,
        "ignored": 0,
    }
    if not artifact_db.exists():
        return stats

    conn = sqlite3.connect(artifact_db)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'hash'"
        ).fetchone()
        if row is None:
            return stats

        stats["table_exists"] = True
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
    return stats


def parse_new_artifacts(log_text: str) -> dict[str, int]:
    """Extract ThreatIngestor's final New artifacts dict from captured logs."""
    matches = NEW_ARTIFACTS_RE.findall(log_text)
    if not matches:
        return {}

    try:
        parsed = ast.literal_eval(matches[-1])
    except (ValueError, SyntaxError):
        return {}
    if not isinstance(parsed, dict):
        return {}

    counts: dict[str, int] = {}
    for key, value in parsed.items():
        try:
            counts[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return counts


def load_json(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return artifact_snapshot()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return artifact_snapshot()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def format_summary(
    *,
    before: dict[str, Any],
    after: dict[str, Any],
    log_text: str,
    exit_code: int,
) -> str:
    new_artifacts = parse_new_artifacts(log_text)
    seen = sum(new_artifacts.values())
    stored = max(0, int(after.get("total", 0)) - int(before.get("total", 0)))
    sha256 = max(0, int(after.get("sha256", 0)) - int(before.get("sha256", 0)))
    queued = max(0, int(after.get("queued", 0)) - int(before.get("queued", 0)))
    ignored = max(0, int(after.get("ignored", 0)) - int(before.get("ignored", 0)))
    status = "ok" if exit_code == 0 else f"exit={exit_code}"

    parts = [
        "ThreatIngestor:",
        f"seen={seen}",
        f"sha256={sha256}",
        f"stored={stored}",
        f"queued={queued}",
        f"ignored={ignored}",
        f"unprocessed={after.get('unprocessed', 0)}",
        f"status={status}",
    ]
    if new_artifacts and seen != sha256:
        breakdown = ",".join(f"{k}:{v}" for k, v in sorted(new_artifacts.items()))
        parts.append(f"raw_artifacts={breakdown}")
    return " ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize ThreatIngestor sidecar output")
    parser.add_argument("--snapshot", type=Path, help="Write a JSON DB snapshot to this path")
    parser.add_argument("--before", type=Path, help="Read the pre-run JSON DB snapshot")
    parser.add_argument("--log", type=Path, help="Read captured ThreatIngestor output")
    parser.add_argument("--exit-code", type=int, default=0)
    args = parser.parse_args()

    if args.snapshot:
        write_json(args.snapshot, artifact_snapshot())
        return

    before = load_json(args.before)
    after = artifact_snapshot()
    log_text = ""
    if args.log and args.log.exists():
        try:
            log_text = args.log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""

    print(
        format_summary(
            before=before,
            after=after,
            log_text=log_text,
            exit_code=args.exit_code,
        )
    )


if __name__ == "__main__":
    main()

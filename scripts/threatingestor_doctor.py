#!/usr/bin/env python3
"""Inspect and repair ThreatIngestor hash artifact state."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.config import THREATINGESTOR_ARTIFACT_DB
from src.intel.threatingestor_artifacts import (
    artifact_state_counts,
    reset_ignored_sha256_artifacts,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect ThreatIngestor artifact DB")
    parser.add_argument("--db", type=Path, default=THREATINGESTOR_ARTIFACT_DB)
    parser.add_argument(
        "--reset-ignored-sha256",
        action="store_true",
        help="Reset ignored SHA256 artifacts to unprocessed for revalidation",
    )
    args = parser.parse_args()

    before = artifact_state_counts(artifact_db=args.db)
    print("before", " ".join(f"{k}={v}" for k, v in sorted(before.items())))
    if args.reset_ignored_sha256:
        reset = reset_ignored_sha256_artifacts(artifact_db=args.db)
        print(f"reset_ignored_sha256={reset}")
        after = artifact_state_counts(artifact_db=args.db)
        print("after", " ".join(f"{k}={v}" for k, v in sorted(after.items())))


if __name__ == "__main__":
    main()

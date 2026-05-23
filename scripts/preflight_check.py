#!/usr/bin/env python3
"""Operational diagnostics before graph bootstrap or daemon startup."""

from __future__ import annotations

import argparse
import sys

from src.collection.context import build_collection_context
from src.config import BENIGN_DIR, MIN_TRAIN_BENIGN, MIN_TRAIN_MALWARE, allow_local_benign
from src.db.tracker import get_tracker
from src.log import PHASE_PREFLIGHT, configure_logging, get_logger, phase_log
from src.ml.classifier import load_bundle, model_bundle_ready, training_targets_met

logger = get_logger("Preflight")


def main() -> int:
    parser = argparse.ArgumentParser(description="AMD-Agent operational preflight")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when phase is steady but model bundle is not ready",
    )
    args = parser.parse_args()
    configure_logging()

    tracker = get_tracker()
    ctx = build_collection_context(tracker)
    bundle = load_bundle()
    counts = tracker.count_by_label()
    bundle_ok = model_bundle_ready(bundle)

    phase_log(logger, PHASE_PREFLIGHT, "=== Operational Diagnostics ===")
    phase_log(
        logger,
        PHASE_PREFLIGHT,
        "Database: malware %d/%d | benign %d/%d",
        ctx.malware_count,
        MIN_TRAIN_MALWARE,
        ctx.benign_count,
        MIN_TRAIN_BENIGN,
    )
    phase_log(logger, PHASE_PREFLIGHT, "Phase: %s", ctx.phase.upper())
    phase_log(logger, PHASE_PREFLIGHT, "Pending queue: %d", ctx.pending_depth)
    phase_log(logger, PHASE_PREFLIGHT, "Model bundle ready: %s", bundle_ok)
    phase_log(logger, PHASE_PREFLIGHT, "training_targets_met: %s", training_targets_met(counts))

    if allow_local_benign():
        logger.warning(
            "[%s] AMD_ALLOW_LOCAL_BENIGN is enabled; disable for submission experiments",
            PHASE_PREFLIGHT,
        )
    local_benign = [
        p for p in BENIGN_DIR.glob("*") if p.is_file() and not p.name.startswith(".")
    ]
    if local_benign:
        logger.warning(
            "[%s] data/benign contains %d file(s); remove or disable local benign for submission",
            PHASE_PREFLIGHT,
            len(local_benign),
        )

    exit_code = 0
    if ctx.phase == "steady" and not bundle_ok:
        logger.warning(
            "[%s] Phase is STEADY but model bundle is stale or missing; "
            "next run may force cold-start retrain",
            PHASE_PREFLIGHT,
        )
        if args.strict:
            exit_code = 1
    elif ctx.phase == "bootstrap" and bundle_ok:
        logger.warning(
            "[%s] Database records do not meet thresholds, but a valid model bundle was found on disk",
            PHASE_PREFLIGHT,
        )

    phase_log(logger, PHASE_PREFLIGHT, "=== Done ===")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

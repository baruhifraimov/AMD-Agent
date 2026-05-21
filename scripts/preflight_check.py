#!/usr/bin/env python3
"""Operational diagnostics before graph bootstrap or daemon startup."""

from __future__ import annotations

import argparse
import logging
import sys

from src.collection.context import build_collection_context
from src.config import BENIGN_DIR, MIN_TRAIN_BENIGN, MIN_TRAIN_MALWARE, allow_local_benign
from src.db.tracker import get_tracker
from src.ml.classifier import load_bundle, model_bundle_ready, training_targets_met

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Preflight")


def main() -> int:
    parser = argparse.ArgumentParser(description="AMD-Agent operational preflight")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when phase is steady but model bundle is not ready",
    )
    args = parser.parse_args()

    tracker = get_tracker()
    ctx = build_collection_context(tracker)
    bundle = load_bundle()
    counts = tracker.count_by_label()
    bundle_ok = model_bundle_ready(bundle)

    logger.info("=== AMD-Agent Operational Diagnostics ===")
    logger.info(
        "Database Balances -> Trainable Malware: %d/%d | Trainable Benign: %d/%d",
        ctx.malware_count,
        MIN_TRAIN_MALWARE,
        ctx.benign_count,
        MIN_TRAIN_BENIGN,
    )
    logger.info("Evaluated Operational Phase -> Phase ID: [%s]", ctx.phase.upper())
    logger.info("Pending Intelligence Depth -> Queue Count: %d", ctx.pending_depth)
    logger.info("Classifier Bundle Integrity -> Ready Status: [%s]", bundle_ok)
    logger.info("training_targets_met -> %s", training_targets_met(counts))

    if allow_local_benign():
        logger.warning(
            "AMD_ALLOW_LOCAL_BENIGN is enabled; disable for submission experiments"
        )
    local_benign = [
        p for p in BENIGN_DIR.glob("*") if p.is_file() and not p.name.startswith(".")
    ]
    if local_benign:
        logger.warning(
            "data/benign contains %d file(s); remove or disable local benign for submission",
            len(local_benign),
        )

    exit_code = 0
    if ctx.phase == "steady" and not bundle_ok:
        logger.warning(
            "Phase is STEADY but model bundle is stale or missing; "
            "next run may force cold-start retrain"
        )
        if args.strict:
            exit_code = 1
    elif ctx.phase == "bootstrap" and bundle_ok:
        logger.warning(
            "Database records do not meet thresholds, but a valid model bundle was found on disk"
        )

    logger.info("=========================================")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

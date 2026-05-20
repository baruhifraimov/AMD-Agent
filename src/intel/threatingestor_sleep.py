"""Dynamic ThreatIngestor poll interval based on bootstrap completion."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

import src.db.tracker as db
from src.config import (
    THREATINGESTOR_CONFIG_PATH,
    THREATINGESTOR_SLEEP_BOOTSTRAP,
    THREATINGESTOR_SLEEP_STEADY,
    ensure_dirs,
)
from src.ml.classifier import training_targets_met

logger = logging.getLogger(__name__)

RUNTIME_CONFIG_PATH = Path("/data/threatingestor_config.runtime.yml")


def bootstrap_collection_complete(tracker: db.MalwareTracker | None = None) -> bool:
    """True when trainable malware and benign counts meet MIN_TRAIN_* targets."""
    tracker = tracker or db.get_tracker()
    return training_targets_met(tracker.count_by_label())


def threatingestor_interval_seconds(tracker: db.MalwareTracker | None = None) -> int:
    """Short interval while collecting initial data; 15m cooldown after."""
    if bootstrap_collection_complete(tracker):
        return THREATINGESTOR_SLEEP_STEADY
    return THREATINGESTOR_SLEEP_BOOTSTRAP


def write_runtime_config(
    *,
    template_path: Path | None = None,
    output_path: Path | None = None,
) -> Path:
    """Emit a single-pass ThreatIngestor config (daemon=false; sleep handled externally)."""
    ensure_dirs()
    template_path = template_path or THREATINGESTOR_CONFIG_PATH
    output_path = output_path or (
        RUNTIME_CONFIG_PATH
        if Path("/data").exists()
        else template_path.parent / "data" / "threatingestor_config.runtime.yml"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with template_path.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    general = dict(config.get("general") or {})
    general["daemon"] = False
    config["general"] = general

    with output_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, default_flow_style=False)

    return output_path


def main() -> None:
    """CLI: print seconds to sleep before the next ThreatIngestor pass."""
    import argparse

    parser = argparse.ArgumentParser(description="Resolve ThreatIngestor poll interval")
    parser.add_argument(
        "--write-runtime-config",
        action="store_true",
        help="Write runtime ThreatIngestor YAML with daemon=false",
    )
    parser.add_argument("--template", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    if args.write_runtime_config:
        path = write_runtime_config(
            template_path=args.template,
            output_path=args.output,
        )
        print(path)
        return

    interval = threatingestor_interval_seconds()
    mode = "steady" if interval == THREATINGESTOR_SLEEP_STEADY else "bootstrap"
    logger.info("ThreatIngestor interval=%ds mode=%s", interval, mode)
    print(interval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    main()

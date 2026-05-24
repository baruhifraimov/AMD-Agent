#!/usr/bin/env python3
"""Generate report figures and narrative from logs and SQLite."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.evaluation.report_figures import backfill_eval_log_from_training_history, generate_all_figures
from src.evaluation.report_narrative import write_report_narrative
import src.config as cfg


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate AMD-Agent report figures from logs.")
    parser.add_argument(
        "--no-narrative",
        action="store_true",
        help="Skip writing report/REPORT.md narrative",
    )
    parser.add_argument(
        "--no-backfill",
        action="store_true",
        help="Skip backfilling evaluation_log from training_history",
    )
    parser.add_argument(
        "--no-live-eval",
        action="store_true",
        help="Do not run live TESSERACT when eval log is sparse",
    )
    args = parser.parse_args()

    cfg.ensure_dirs()
    added = 0
    if not args.no_backfill:
        added = backfill_eval_log_from_training_history(run_live_eval=not args.no_live_eval)

    paths = generate_all_figures(backfill=False, run_live_eval=False)
    narrative_path = None
    if not args.no_narrative:
        narrative_path = write_report_narrative()

    from src.evaluation.report_figures import read_jsonl

    n_eval = len(read_jsonl(cfg.EVAL_LOG_PATH))
    print(f"Backfilled eval log rows: {added}")
    print(f"evaluation_log.jsonl total lines: {n_eval}")
    for name, path in paths.items():
        print(f"Wrote [{name}]: {path}")
    if narrative_path:
        print(f"Wrote narrative: {narrative_path}")


if __name__ == "__main__":
    main()

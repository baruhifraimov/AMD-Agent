"""Evaluation utilities (TESSERACT temporal methodology)."""

from src.evaluation.tesseract import (
    append_eval_log,
    compute_aut,
    compute_metrics,
    plot_performance_decay,
    run_tesseract_eval,
)

__all__ = [
    "compute_metrics",
    "run_tesseract_eval",
    "append_eval_log",
    "plot_performance_decay",
    "compute_aut",
]

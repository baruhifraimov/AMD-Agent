"""Evaluation utilities (TESSERACT temporal methodology, drift reporting)."""

from src.evaluation.drift_log import append_drift_log, build_drift_record

__all__ = [
    "compute_metrics",
    "run_tesseract_eval",
    "append_eval_log",
    "latest_eval_metrics",
    "append_drift_log",
    "build_drift_record",
    "plot_performance_decay",
    "compute_aut",
]


def __getattr__(name: str):
    if name in (
        "compute_metrics",
        "run_tesseract_eval",
        "append_eval_log",
        "latest_eval_metrics",
        "plot_performance_decay",
        "compute_aut",
    ):
        from src.evaluation import tesseract

        return getattr(tesseract, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

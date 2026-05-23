"""Evaluation utilities (TESSERACT temporal methodology, drift reporting)."""

from src.evaluation.drift_log import append_drift_log, build_drift_record

__all__ = [
    "compute_metrics",
    "run_tesseract_eval",
    "append_eval_log",
    "latest_eval_metrics",
    "append_drift_log",
    "build_drift_record",
    "append_model_update_log",
    "build_model_update_record",
    "evaluate_bundle_on_current_holdout",
    "log_model_update_summary",
    "record_model_update_comparison",
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
    if name in (
        "append_model_update_log",
        "build_model_update_record",
        "evaluate_bundle_on_current_holdout",
        "log_model_update_summary",
        "record_model_update_comparison",
    ):
        from src.evaluation import model_update

        return getattr(model_update, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

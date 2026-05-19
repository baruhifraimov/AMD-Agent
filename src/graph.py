"""LangGraph workflow for continual malware detection."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
import time
from typing import Literal

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

import src.db.tracker as db
from src.config import MIN_TRAIN_BENIGN, MIN_TRAIN_MALWARE, ensure_dirs
from src.ml.classifier import load_bundle
from src.nodes import (
    active_learning_explain,
    binary_fetch,
    classifier_inference,
    consume_threatingestor_queue,
    data_validation,
    drift_monitor,
    feature_extraction,
    model_retrain,
    source_discovery,
    source_selector,
)
from src.runtime.scheduler import SchedulerLoop, load_scheduler_config
from src.state import AgentState

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def _wrap(node_fn):
    """Adapt node to merge partial dict into Pydantic state."""

    def inner(state: AgentState) -> dict:
        updates = node_fn(state)
        merged = AgentState.model_validate({**state.model_dump(), **updates})
        return merged.model_dump()

    return inner


def route_after_drift(state: AgentState) -> Literal["inference", "retrain"]:
    return "retrain" if state.drift_detected else "inference"


def route_after_selector(state: AgentState) -> Literal["benign_discovery", "malware_queue"]:
    if state.expected_label == 0:
        return "benign_discovery"
    return "malware_queue"


def route_after_threat_queue(state: AgentState) -> Literal["binary_fetch", "source_discovery"]:
    if state.sample_candidates:
        return "binary_fetch"
    return "source_discovery"


DEFAULT_THREAD_ID = "amd-agent-default"
_CHECKPOINTER = MemorySaver()
DEFAULT_BOOTSTRAP_MAX_RUNS = 10
DEFAULT_BOOTSTRAP_INTERVAL = 5


def build_graph():
    """Build and compile the agent StateGraph."""
    graph = StateGraph(AgentState)

    graph.add_node("source_selector", _wrap(source_selector))
    graph.add_node("threat_queue", _wrap(consume_threatingestor_queue))
    graph.add_node("source_discovery", _wrap(source_discovery))
    graph.add_node("binary_fetch", _wrap(binary_fetch))
    graph.add_node("data_validation", _wrap(data_validation))
    graph.add_node("feature_extraction", _wrap(feature_extraction))
    graph.add_node("drift_monitor", _wrap(drift_monitor))
    graph.add_node("classifier_inference", _wrap(classifier_inference))
    graph.add_node("active_learning_explain", _wrap(active_learning_explain))
    graph.add_node("model_retrain", _wrap(model_retrain))

    graph.add_edge(START, "source_selector")
    graph.add_conditional_edges(
        "source_selector",
        route_after_selector,
        {
            "benign_discovery": "source_discovery",
            "malware_queue": "threat_queue",
        },
    )
    graph.add_conditional_edges(
        "threat_queue",
        route_after_threat_queue,
        {
            "binary_fetch": "binary_fetch",
            "source_discovery": "source_discovery",
        },
    )
    graph.add_edge("source_discovery", "binary_fetch")
    graph.add_edge("binary_fetch", "data_validation")
    graph.add_edge("data_validation", "feature_extraction")
    graph.add_edge("feature_extraction", "drift_monitor")
    graph.add_conditional_edges(
        "drift_monitor",
        route_after_drift,
        {
            "inference": "classifier_inference",
            "retrain": "active_learning_explain",
        },
    )
    graph.add_edge("classifier_inference", END)
    graph.add_edge("active_learning_explain", "model_retrain")
    graph.add_edge("model_retrain", END)

    return graph.compile(checkpointer=_CHECKPOINTER)


def run_pipeline() -> AgentState:
    """Execute one full graph pass."""
    ensure_dirs()
    graph = build_graph()
    result = graph.invoke(
        AgentState(),
        config={"configurable": {"thread_id": DEFAULT_THREAD_ID}},
    )
    final = AgentState.model_validate(result)
    logger.info(
        "Run complete: source=%s label=%d hashes=%d predictions=%d drift=%s",
        final.source_type,
        final.expected_label,
        len(final.discovered_hashes),
        len(final.predictions),
        final.drift_detected,
    )
    if final.semantic_report:
        logger.info("Report: %s", final.semantic_report)

    try:
        from src.evaluation import append_eval_log, plot_performance_decay, run_tesseract_eval

        metrics = run_tesseract_eval()
        if metrics:
            append_eval_log(metrics)
            plot_performance_decay()
            logger.info("TESSERACT eval: %s", metrics)
    except Exception as exc:
        logger.debug("Post-run eval skipped: %s", exc)

    return final


def run_bootstrap() -> AgentState | None:
    """Run repeated graph passes until the initial model is ready or safety limit is hit."""
    max_runs = _env_int("AMD_BOOTSTRAP_MAX_RUNS", DEFAULT_BOOTSTRAP_MAX_RUNS)
    interval_seconds = _env_int("AMD_BOOTSTRAP_INTERVAL", DEFAULT_BOOTSTRAP_INTERVAL)
    final: AgentState | None = None

    logger.info(
        "Bootstrap started max_runs=%d interval=%ds target_malware=%d target_benign=%d",
        max_runs,
        interval_seconds,
        MIN_TRAIN_MALWARE,
        MIN_TRAIN_BENIGN,
    )
    for run_idx in range(1, max_runs + 1):
        logger.info("Bootstrap pass %d/%d", run_idx, max_runs)
        final = run_pipeline()
        if load_bundle() is not None:
            logger.info("Bootstrap complete: model bundle is ready")
            return final

        counts = db.get_tracker().count_by_label()
        n_mal = counts.get(1, 0)
        n_ben = counts.get(0, 0)
        logger.info(
            "Bootstrap awaiting model: malware=%d/%d benign=%d/%d",
            n_mal,
            MIN_TRAIN_MALWARE,
            n_ben,
            MIN_TRAIN_BENIGN,
        )
        if run_idx < max_runs and interval_seconds > 0:
            time.sleep(interval_seconds)

    logger.warning("Bootstrap stopped before model was ready; increase AMD_BOOTSTRAP_MAX_RUNS")
    return final


def main() -> None:
    parser = argparse.ArgumentParser(description="AMD-Agent malware detection pipeline")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Run pipeline once (default)")
    mode.add_argument("--daemon", action="store_true", help="Run pipeline on a schedule")
    mode.add_argument(
        "--bootstrap",
        action="store_true",
        help="Run repeated passes until the initial model is ready",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional scheduler YAML (merged over env vars)",
    )
    args = parser.parse_args()

    if args.daemon:
        sched_cfg = load_scheduler_config(args.config)
        sched_cfg.enabled = True
        SchedulerLoop(sched_cfg).run(run_pipeline)
    elif args.bootstrap:
        run_bootstrap()
    else:
        run_pipeline()


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    return int(raw) if raw else default


if __name__ == "__main__":
    main()

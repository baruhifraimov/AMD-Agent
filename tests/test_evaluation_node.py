"""Tests for LangGraph evaluation node."""

from unittest.mock import patch

import pytest

from src.nodes.evaluation_node import evaluation_node
from src.state import AgentState


@patch("src.evaluation.tesseract.plot_performance_decay")
@patch("src.evaluation.tesseract.append_eval_log")
@patch("src.evaluation.tesseract.run_tesseract_eval", return_value={})
@patch("src.nodes.evaluation_node._should_warn_empty_eval", return_value=False)
def test_evaluation_node_empty_metrics_no_raise(
    mock_warn, mock_eval, mock_append, mock_plot
):
    state = AgentState(evaluation_metrics={"model_ready": 1.0})
    out = evaluation_node(state)
    assert out["evaluation_metrics"]["model_ready"] == 1.0
    mock_append.assert_not_called()
    mock_plot.assert_not_called()


@patch("src.evaluation.tesseract.plot_performance_decay")
@patch("src.evaluation.tesseract.append_eval_log")
@patch(
    "src.evaluation.tesseract.run_tesseract_eval",
    return_value={"accuracy": 0.91, "fpr": 0.002},
)
def test_evaluation_node_appends_eval_log(mock_eval, mock_append, mock_plot, tmp_paths):
    state = AgentState()
    out = evaluation_node(state)
    assert out["evaluation_metrics"]["accuracy"] == 0.91
    mock_append.assert_called_once()
    mock_plot.assert_called_once()


@patch("src.nodes.evaluation_node.append_drift_log")
@patch("src.evaluation.tesseract.plot_performance_decay")
@patch("src.evaluation.tesseract.append_eval_log")
@patch(
    "src.evaluation.tesseract.run_tesseract_eval",
    return_value={"accuracy": 0.88, "fpr": 0.003},
)
def test_evaluation_node_logs_drift_when_pending(
    mock_eval, mock_append, mock_plot, mock_drift_log
):
    state = AgentState(
        pending_drift_log=True,
        drift_pre_metrics={"accuracy": 0.8},
        drift_stats={"mean_shift": 1.2},
        evaluation_metrics={"retrained": 1.0, "new_batch_size": 1.0},
    )
    out = evaluation_node(state)
    assert out["pending_drift_log"] is False
    mock_drift_log.assert_called_once()
    record = mock_drift_log.call_args[0][0]
    assert record["pre_metrics"]["accuracy"] == 0.8
    assert record["post_metrics"]["accuracy"] == 0.88


@patch("src.evaluation.tesseract.run_tesseract_eval", side_effect=RuntimeError("eval boom"))
def test_evaluation_node_raises_on_exception(mock_eval):
    with pytest.raises(RuntimeError, match="eval boom"):
        evaluation_node(AgentState())

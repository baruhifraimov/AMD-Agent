"""LangGraph routing and graph compile smoke tests."""

from unittest.mock import patch

from src.graph import (
    build_graph,
    route_after_drift,
    route_after_pe_discovery,
    route_after_selector,
)
from src.state import AgentState


def test_route_after_drift():
    assert route_after_drift(AgentState(drift_detected=False)) == "inference"
    assert route_after_drift(AgentState(drift_detected=True)) == "retrain"
    assert route_after_drift(AgentState(threshold_retrain=True)) == "model_retrain"


@patch("src.graph.build_collection_context")
def test_route_after_selector_steady_vs_bootstrap(mock_ctx):
    from src.collection.context import CollectionContext

    mock_ctx.return_value = CollectionContext(
        benign_count=100, malware_count=100, model_ready=True, pending_depth=0
    )
    assert route_after_selector(AgentState(expected_label=0)) == "source_discovery"
    assert route_after_selector(AgentState(expected_label=1, collection_phase="bootstrap")) == "source_discovery"

    mock_ctx.return_value = CollectionContext(
        benign_count=50, malware_count=50, model_ready=False, pending_depth=0
    )
    assert (
        route_after_selector(AgentState(expected_label=1, collection_phase="steady"))
        == "source_discovery"
    )


@patch("src.graph.PE_SOURCE_DISCOVERY_ENABLED", True)
@patch("src.graph.PESourceStore")
def test_route_pe_source_discovery_when_sparse(mock_store):
    mock_store.return_value.count_active.return_value = 0
    with patch("src.graph.build_collection_context") as mock_ctx:
        from src.collection.context import CollectionContext

        mock_ctx.return_value = CollectionContext(
            benign_count=100, malware_count=100, model_ready=True, pending_depth=0
        )
        assert route_after_selector(AgentState(expected_label=1, collection_phase="steady")) == "pe_source_discovery"


def test_route_after_pe_discovery():
    assert route_after_pe_discovery(AgentState(route_hint="source_discovery")) == "source_discovery"


def test_build_graph_includes_evaluation_node():
    assert "evaluation" in set(build_graph().get_graph().nodes.keys())

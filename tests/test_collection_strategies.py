"""Tests for bootstrap vs steady collection strategies."""

from unittest.mock import patch

from src.collection.context import CollectionContext
from src.collection.factory import CollectionStrategyFactory
from src.collection.strategies.bootstrap import BootstrapSelectionStrategy
from src.collection.strategies.steady import SteadyStateSelectionStrategy
from src.sources.github_releases import GitHubReleasesProvider
from src.sources.malwarebazaar import MalwareBazaarProvider
from src.sources.registry import SourceRegistry
from src.sources.sysinternals import SysinternalsProvider


def _registry() -> SourceRegistry:
    reg = SourceRegistry()
    reg.register(MalwareBazaarProvider())
    reg.register(SysinternalsProvider())
    reg.register(GitHubReleasesProvider())
    return reg


@patch("src.collection.strategies.bootstrap.get_registry", side_effect=lambda: _registry())
def test_bootstrap_selects_benign_when_deficit(mock_reg):
    ctx = CollectionContext(benign_count=0, malware_count=50, model_ready=False, pending_depth=0)
    result = BootstrapSelectionStrategy().select(ctx)
    assert result.expected_label == 0
    assert result.collection_phase == "bootstrap"
    assert result.source_type in ("sysinternals", "github")


@patch("src.collection.strategies.bootstrap.get_registry", side_effect=lambda: _registry())
def test_bootstrap_prefers_malware_on_equal_deficit_tie(mock_reg):
    ctx = CollectionContext(benign_count=90, malware_count=90, model_ready=False, pending_depth=0)
    result = BootstrapSelectionStrategy().select(ctx)
    assert result.expected_label == 1
    assert result.source_type == "malwarebazaar"


@patch("src.collection.strategies.bootstrap.get_registry", side_effect=lambda: _registry())
def test_bootstrap_prefers_malware_when_malware_deficit_larger(mock_reg):
    ctx = CollectionContext(benign_count=98, malware_count=56, model_ready=False, pending_depth=0)
    result = BootstrapSelectionStrategy().select(ctx)
    assert result.expected_label == 1
    assert result.source_type == "malwarebazaar"


@patch("src.collection.strategies.bootstrap.get_registry", side_effect=lambda: _registry())
def test_bootstrap_selects_malwarebazaar_when_benign_satisfied(mock_reg):
    ctx = CollectionContext(benign_count=100, malware_count=10, model_ready=False, pending_depth=0)
    result = BootstrapSelectionStrategy().select(ctx)
    assert result.expected_label == 1
    assert result.source_type == "malwarebazaar"
    assert result.discovery_strategy == "bootstrap_fast_path"


@patch("src.collection.strategies.steady.get_registry", side_effect=lambda: _registry())
def test_steady_pending_routes_to_intel(mock_reg):
    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=2)
    result = SteadyStateSelectionStrategy().select(ctx)
    assert result.route_hint == "threat_intel_ingest"
    assert result.selected_sources == ["malwarebazaar"]


@patch("src.collection.strategies.steady.get_registry", side_effect=lambda: _registry())
def test_steady_without_pending_routes_to_intel_poll(mock_reg):
    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=0)
    result = SteadyStateSelectionStrategy().select(ctx)
    assert result.route_hint == "threat_intel_ingest"
    assert result.discovery_strategy == "steady_intel_poll"
    assert result.collection_phase == "steady"


def test_factory_picks_bootstrap_when_counts_below_target():
    ctx = CollectionContext(benign_count=50, malware_count=50, model_ready=True, pending_depth=0)
    assert ctx.phase == "bootstrap"
    strategy = CollectionStrategyFactory.create(ctx)
    assert strategy.__class__.__name__ == "BootstrapSelectionStrategy"


def test_phase_steady_only_from_db_counts():
    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=False, pending_depth=0)
    assert ctx.phase == "steady"


def test_phase_bootstrap_when_model_ready_but_counts_low():
    ctx = CollectionContext(benign_count=100, malware_count=50, model_ready=True, pending_depth=0)
    assert ctx.phase == "bootstrap"

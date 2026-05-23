"""Tests for bootstrap vs steady collection strategies."""

from unittest.mock import MagicMock, patch

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


def _tracker(*, healthy: bool = True, counter: int = 1):
    tracker = MagicMock()
    tracker.rank_providers_by_yield.side_effect = lambda names, _label: list(names)
    tracker.is_provider_cooled_down.return_value = False
    tracker.temporal_split_health.return_value = {"healthy": healthy}
    tracker.increment_collection_counter.return_value = counter
    return tracker


@patch("src.collection.strategies.bootstrap.get_registry", side_effect=lambda: _registry())
def test_bootstrap_selects_mixed_when_both_labels_need_samples(mock_reg):
    ctx = CollectionContext(benign_count=0, malware_count=50, model_ready=False, pending_depth=0)
    result = BootstrapSelectionStrategy(tracker=_tracker()).select(ctx)
    assert result.expected_label == -1
    assert result.collection_phase == "bootstrap"
    assert result.source_type == "mixed"
    assert result.discovery_strategy == "bootstrap_mixed_balance"
    assert set(result.selected_sources) == {"malwarebazaar", "sysinternals", "github"}


@patch("src.collection.strategies.bootstrap.get_registry", side_effect=lambda: _registry())
def test_bootstrap_equal_deficit_uses_mixed(mock_reg):
    ctx = CollectionContext(benign_count=90, malware_count=90, model_ready=False, pending_depth=0)
    result = BootstrapSelectionStrategy(tracker=_tracker()).select(ctx)
    assert result.expected_label == -1
    assert result.source_type == "mixed"


@patch("src.collection.strategies.bootstrap.get_registry", side_effect=lambda: _registry())
def test_bootstrap_uses_mixed_when_malware_deficit_larger_but_benign_needed(mock_reg):
    ctx = CollectionContext(benign_count=98, malware_count=56, model_ready=False, pending_depth=0)
    result = BootstrapSelectionStrategy(tracker=_tracker()).select(ctx)
    assert result.expected_label == -1
    assert result.source_type == "mixed"


@patch("src.collection.strategies.bootstrap.get_registry", side_effect=lambda: _registry())
def test_bootstrap_selects_malwarebazaar_when_benign_satisfied(mock_reg):
    ctx = CollectionContext(benign_count=100, malware_count=10, model_ready=False, pending_depth=0)
    result = BootstrapSelectionStrategy(tracker=_tracker()).select(ctx)
    assert result.expected_label == 1
    assert result.source_type == "malwarebazaar"
    assert result.discovery_strategy == "bootstrap_fast_path"


@patch("src.collection.strategies.steady.get_registry", side_effect=lambda: _registry())
def test_steady_pending_uses_active_malware_discovery(mock_reg):
    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=2)
    result = SteadyStateSelectionStrategy(tracker=_tracker()).select(ctx)
    assert result.route_hint == "source_discovery"
    assert result.selected_sources == ["malwarebazaar"]
    assert result.discovery_strategy == "steady_malware_active"


@patch("src.collection.strategies.steady.get_registry", side_effect=lambda: _registry())
def test_steady_selects_all_benign_sources_when_benign_needed(mock_reg):
    ctx = CollectionContext(benign_count=100, malware_count=130, model_ready=True, pending_depth=0)
    result = SteadyStateSelectionStrategy(tracker=_tracker()).select(ctx)
    assert result.expected_label == 0
    assert set(result.selected_sources) == {"sysinternals", "github"}


@patch("src.collection.strategies.steady.get_registry", side_effect=lambda: _registry())
def test_steady_without_pending_uses_active_malware_discovery(mock_reg):
    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=0)
    result = SteadyStateSelectionStrategy(tracker=_tracker()).select(ctx)
    assert result.route_hint == "source_discovery"
    assert result.discovery_strategy == "steady_malware_active"
    assert result.collection_phase == "steady"


@patch("src.collection.strategies.steady.get_registry", side_effect=lambda: _registry())
def test_steady_uses_mixed_until_temporal_split_healthy(mock_reg):
    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=0)
    result = SteadyStateSelectionStrategy(tracker=_tracker(healthy=False)).select(ctx)
    assert result.expected_label == -1
    assert result.discovery_strategy == "steady_temporal_mixed"


@patch("src.collection.strategies.steady.get_registry", side_effect=lambda: _registry())
def test_steady_every_fourth_run_refreshes_benign(mock_reg):
    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=0)
    result = SteadyStateSelectionStrategy(tracker=_tracker(counter=4)).select(ctx)
    assert result.expected_label == 0
    assert result.discovery_strategy == "steady_benign_refresh"


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

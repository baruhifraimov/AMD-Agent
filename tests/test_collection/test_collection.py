"""Collection strategies and discovery chain."""

from unittest.mock import MagicMock, patch

from src.collection.context import CollectionContext
from src.collection.discovery_chain import discover_active_malware_sources, discover_with_fallback
from src.collection.provider_stats import summarize_discovery_providers
from src.collection.factory import CollectionStrategyFactory
from src.collection.strategies.bootstrap import BootstrapSelectionStrategy
from src.collection.strategies.steady import SteadyStateSelectionStrategy
from src.sources.base import SampleCandidate
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
def test_bootstrap_mixed_when_both_labels_need_samples(_mock_reg):
    ctx = CollectionContext(benign_count=10, malware_count=10, model_ready=False, pending_depth=0)
    result = BootstrapSelectionStrategy(tracker=_tracker()).select(ctx)
    assert result.expected_label == -1
    assert result.collection_phase == "bootstrap"
    assert result.discovery_strategy == "bootstrap_mixed_balance"


@patch("src.collection.strategies.steady.get_registry", side_effect=lambda: _registry())
def test_steady_pending_uses_active_malware_discovery(_mock_reg):
    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=2)
    result = SteadyStateSelectionStrategy(tracker=_tracker()).select(ctx)
    assert result.route_hint == "source_discovery"
    assert result.discovery_strategy == "steady_malware_active"


def test_factory_picks_bootstrap_when_counts_below_target():
    ctx = CollectionContext(benign_count=10, malware_count=10, model_ready=True, pending_depth=0)
    assert ctx.phase == "bootstrap"
    assert CollectionStrategyFactory.create(ctx).__class__.__name__ == "BootstrapSelectionStrategy"


def _candidate(prefix: str, provider: str) -> SampleCandidate:
    sha = prefix * 64
    return SampleCandidate(sha, provider, 1, {"sha256": sha})


def _make_registry(mb_discover, tf_discover=None):
    mb = MagicMock()
    mb.name = "malwarebazaar"
    mb.expected_label = 1
    mb.discover.side_effect = mb_discover
    tf = MagicMock()
    tf.name = "threatfox"
    tf.expected_label = 1
    tf.discover.side_effect = tf_discover or (lambda _limit: [])
    registry = MagicMock()
    registry.list_names.return_value = ["malwarebazaar", "threatfox"]

    def get(name):
        return mb if name == "malwarebazaar" else tf

    registry.get.side_effect = get
    return registry, mb, tf


def test_malwarebazaar_empty_continues_fallbacks(monkeypatch):
    monkeypatch.setattr(
        "src.collection.discovery_chain.MALWARE_FALLBACK_PROVIDERS",
        ("threatfox",),
    )
    sha = "x" * 64
    registry, _mb, tf = _make_registry(
        mb_discover=lambda _limit: [],
        tf_discover=lambda _limit: [SampleCandidate(sha, "threatfox", 1, {"sha256": sha})],
    )
    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False
    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)
    out = discover_with_fallback(
        ["malwarebazaar"], registry=registry, tracker=tracker, ctx=ctx, expected_label=1, limit=5
    )
    assert len(out) == 1
    assert out[0].provider == "threatfox"


def test_malwarebazaar_full_batch_skips_fallbacks():
    registry, _mb, tf = _make_registry(
        mb_discover=lambda _limit: [_candidate(str(i), "malwarebazaar") for i in range(5)],
    )
    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False
    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)
    out = discover_with_fallback(
        ["malwarebazaar"], registry=registry, tracker=tracker, ctx=ctx, expected_label=1, limit=5
    )
    assert len(out) == 5
    tf.discover.assert_not_called()


def test_pending_hash_excluded_from_discovery():
    sha = "a" * 64
    mb = MagicMock()
    mb.name = "malwarebazaar"
    mb.expected_label = 1
    mb.discover.return_value = [SampleCandidate(sha, "malwarebazaar", 1, {"sha256": sha})]
    registry = MagicMock()
    registry.list_names.return_value = ["malwarebazaar"]
    registry.get.return_value = mb
    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = True
    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=1)
    assert (
        discover_with_fallback(
            ["malwarebazaar"],
            registry=registry,
            tracker=tracker,
            ctx=ctx,
            expected_label=1,
            limit=5,
        )
        == []
    )


@patch("src.collection.discovery_chain.malshare_enabled", return_value=True)
def test_active_malware_split_mb_malshare(_malshare_on, monkeypatch):
    monkeypatch.setenv("MALWAREBAZAAR_AUTH_KEY", "test-key")
    mb = MagicMock()
    mb.name = "malwarebazaar"
    mb.expected_label = 1
    mb.discover.return_value = [_candidate(p, "malwarebazaar") for p in ("a", "b", "c")]
    ms = MagicMock()
    ms.name = "malshare"
    ms.expected_label = 1
    ms.discover.return_value = [_candidate(p, "malshare") for p in ("d", "e")]
    registry = MagicMock()
    registry.list_names.return_value = ["malwarebazaar", "malshare"]
    registry.get.side_effect = lambda n: mb if n == "malwarebazaar" else ms
    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False
    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)
    out = discover_active_malware_sources(
        ["malwarebazaar"], registry=registry, tracker=tracker, ctx=ctx, limit=5
    )
    assert len(out) == 5
    assert sum(1 for c in out if c.provider == "malwarebazaar") == 3
    assert sum(1 for c in out if c.provider == "malshare") == 2


def test_summarize_discovery_providers():
    assert summarize_discovery_providers([]) == "no providers"
    summary = summarize_discovery_providers(
        [
            {"provider": "github", "returned": 5, "discovered": 10},
            {"provider": "malwarebazaar", "returned": 0, "discovered": 12},
            {"provider": "otx_pulse_cti", "error": "timeout"},
        ]
    )
    assert summary == "github(5), malwarebazaar(0/12), otx_pulse_cti(error)"

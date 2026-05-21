"""Tests for discovery chain dynamic_cti, ThreatFox, and Twitter fallbacks."""

from unittest.mock import MagicMock, patch

from src.collection.context import CollectionContext
from src.collection.discovery_chain import discover_with_fallback
from src.sources.base import SampleCandidate


def _candidate(prefix: str, provider: str) -> SampleCandidate:
    sha = prefix * 64
    return SampleCandidate(sha, provider, 1, {"sha256": sha})


def _make_registry(mb_discover, tf_discover=None, tw_discover=None):
    mb = MagicMock()
    mb.name = "malwarebazaar"
    mb.expected_label = 1
    mb.discover.side_effect = mb_discover

    tf = MagicMock()
    tf.name = "threatfox"
    tf.expected_label = 1
    tf.discover.side_effect = tf_discover or (lambda _limit: [])

    tw = MagicMock()
    tw.name = "twitter"
    tw.expected_label = 1
    tw.discover.side_effect = tw_discover or (lambda _limit: [])

    registry = MagicMock()
    registry.list_names.return_value = [
        "malwarebazaar",
        "threatfox",
        "twitter",
        "dynamic_cti",
    ]

    def get(name):
        if name == "malwarebazaar":
            return mb
        if name == "threatfox":
            return tf
        if name == "twitter":
            return tw
        raise KeyError(name)

    registry.get.side_effect = get
    return registry, mb, tf, tw


@patch("src.intel.collector.ThreatIntelCollector")
def test_malwarebazaar_empty_continues_fallbacks_until_limit(mock_coll_cls):
    sha = "x" * 64
    mock_coll_cls.return_value.web_discover.return_value = []
    registry, mb, tf, tw = _make_registry(
        mb_discover=lambda _limit: [],
        tf_discover=lambda _limit: [SampleCandidate(sha, "threatfox", 1, {"sha256": sha})],
    )

    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False

    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)
    out = discover_with_fallback(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        expected_label=1,
        limit=5,
    )
    assert len(out) == 1
    assert out[0].provider == "threatfox"
    tw.discover.assert_called_once()
    mock_coll_cls.return_value.web_discover.assert_called_once()


@patch("src.intel.collector.ThreatIntelCollector")
def test_malwarebazaar_full_batch_does_not_call_fallbacks(mock_coll_cls):
    registry, _mb, tf, tw = _make_registry(
        mb_discover=lambda _limit: [_candidate(str(i), "malwarebazaar") for i in range(5)],
    )

    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False

    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)
    out = discover_with_fallback(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        expected_label=1,
        limit=5,
    )
    assert len(out) == 5
    tf.discover.assert_not_called()
    tw.discover.assert_not_called()
    mock_coll_cls.return_value.web_discover.assert_not_called()


@patch("src.intel.collector.ThreatIntelCollector")
def test_partial_batches_fill_from_fallbacks_before_dynamic_cti(mock_coll_cls):
    registry, _mb, _tf, tw = _make_registry(
        mb_discover=lambda _limit: [_candidate("a", "malwarebazaar")],
        tf_discover=lambda _limit: [
            _candidate("b", "threatfox"),
            _candidate("c", "threatfox"),
        ],
        tw_discover=lambda _limit: [
            _candidate("d", "twitter"),
            _candidate("e", "twitter"),
        ],
    )

    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False

    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)
    out = discover_with_fallback(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        expected_label=1,
        limit=5,
    )
    assert [c.provider for c in out] == [
        "malwarebazaar",
        "threatfox",
        "threatfox",
        "twitter",
        "twitter",
    ]
    tw.discover.assert_called_once()
    mock_coll_cls.return_value.web_discover.assert_not_called()


@patch("src.intel.collector.ThreatIntelCollector")
def test_malwarebazaar_empty_uses_twitter_before_dynamic_cti(mock_coll_cls):
    sha = "t" * 64
    mock_coll_cls.return_value.web_discover.return_value = []
    registry, _mb, _tf, tw = _make_registry(
        mb_discover=lambda _limit: [],
        tf_discover=lambda _limit: [],
        tw_discover=lambda _limit: [SampleCandidate(sha, "twitter", 1, {"sha256": sha})],
    )

    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False

    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)
    out = discover_with_fallback(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        expected_label=1,
        limit=5,
    )
    assert len(out) == 1
    assert out[0].provider == "twitter"
    mock_coll_cls.return_value.web_discover.assert_called_once()


@patch("src.intel.collector.ThreatIntelCollector")
def test_malwarebazaar_empty_falls_back_to_dynamic_cti_when_all_providers_empty(mock_coll_cls):
    registry, _mb, _tf, _tw = _make_registry(
        mb_discover=lambda _limit: [],
        tf_discover=lambda _limit: [],
        tw_discover=lambda _limit: [],
    )

    mock_coll = mock_coll_cls.return_value
    mock_coll.web_discover.return_value = [
        SampleCandidate("y" * 64, "dynamic_cti", 1, {"sha256": "y" * 64})
    ]

    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False

    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)
    out = discover_with_fallback(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        expected_label=1,
        limit=5,
    )
    assert len(out) == 1
    assert out[0].provider == "dynamic_cti"
    mock_coll.web_discover.assert_called_once()


@patch("src.intel.collector.ThreatIntelCollector")
def test_steady_phase_also_falls_back_to_ddg(mock_coll_cls):
    registry, _mb, _tf, _tw = _make_registry(
        mb_discover=lambda _limit: [],
        tf_discover=lambda _limit: [],
        tw_discover=lambda _limit: [],
    )

    mock_coll = mock_coll_cls.return_value
    mock_coll.web_discover.return_value = [
        SampleCandidate("z" * 64, "dynamic_cti", 1, {"sha256": "z" * 64})
    ]

    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False

    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=0)
    assert ctx.phase == "steady"
    out = discover_with_fallback(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        expected_label=1,
        limit=5,
        cti_queries=["malware sha256 pe"],
    )
    assert len(out) == 1
    mock_coll.web_discover.assert_called_once_with(5, queries=["malware sha256 pe"])


@patch("src.intel.collector.ThreatIntelCollector")
def test_configured_fallback_chain_can_skip_low_yield_providers(mock_coll_cls, monkeypatch):
    monkeypatch.setattr("src.collection.discovery_chain.MALWARE_FALLBACK_PROVIDERS", ("threatfox",))
    registry, _mb, tf, tw = _make_registry(
        mb_discover=lambda _limit: [],
        tf_discover=lambda _limit: [],
        tw_discover=lambda _limit: [SampleCandidate("t" * 64, "twitter", 1, {"sha256": "t" * 64})],
    )

    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False

    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)
    out = discover_with_fallback(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=ctx,
        expected_label=1,
        limit=5,
    )
    assert out == []
    tf.discover.assert_called_once()
    tw.discover.assert_not_called()
    mock_coll_cls.return_value.web_discover.assert_not_called()


@patch("src.intel.collector.ThreatIntelCollector")
def test_dynamic_cti_fallback_when_ctx_none(mock_coll_cls):
    registry, _mb, _tf, _tw = _make_registry(
        mb_discover=lambda _limit: [],
        tf_discover=lambda _limit: [],
        tw_discover=lambda _limit: [],
    )

    mock_coll = mock_coll_cls.return_value
    mock_coll.web_discover.return_value = [
        SampleCandidate("z" * 64, "dynamic_cti", 1, {"sha256": "z" * 64})
    ]

    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False
    tracker.count_by_label.return_value = {0: 100, 1: 100}

    out = discover_with_fallback(
        ["malwarebazaar"],
        registry=registry,
        tracker=tracker,
        ctx=None,
        expected_label=1,
        limit=5,
    )
    assert len(out) == 1
    assert out[0].provider == "dynamic_cti"
    mock_coll.web_discover.assert_called_once()

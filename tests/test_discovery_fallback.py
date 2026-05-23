"""Tests for discovery chain fallback behaviour."""

from unittest.mock import MagicMock, patch

from src.collection.context import CollectionContext
from src.collection.discovery_chain import discover_active_malware_sources, discover_with_fallback
from src.sources.base import SampleCandidate


def _candidate(prefix: str, provider: str) -> SampleCandidate:
    sha = prefix * 64
    return SampleCandidate(sha, provider, 1, {"sha256": sha})


def _make_registry(mb_discover, tf_discover=None, tw_discover=None, otx_discover=None):
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

    otx = MagicMock()
    otx.name = "otx_pulse_cti"
    otx.expected_label = 1
    otx.discover.side_effect = otx_discover or (lambda _limit: [])

    registry = MagicMock()
    registry.list_names.return_value = [
        "malwarebazaar",
        "threatfox",
        "twitter",
        "otx_pulse_cti",
    ]

    def get(name):
        if name == "malwarebazaar":
            return mb
        if name == "threatfox":
            return tf
        if name == "twitter":
            return tw
        if name == "otx_pulse_cti":
            return otx
        raise KeyError(name)

    registry.get.side_effect = get
    return registry, mb, tf, tw, otx


def _use_legacy_malware_fallback_chain(monkeypatch):
    monkeypatch.setattr(
        "src.collection.discovery_chain.MALWARE_FALLBACK_PROVIDERS",
        ("threatfox", "twitter", "otx_pulse_cti"),
    )


def _active_registry(mb_discover, ms_discover):
    mb = MagicMock()
    mb.name = "malwarebazaar"
    mb.expected_label = 1
    mb.discover.side_effect = mb_discover

    ms = MagicMock()
    ms.name = "malshare"
    ms.expected_label = 1
    ms.discover.side_effect = ms_discover

    registry = MagicMock()
    registry.list_names.return_value = ["malwarebazaar", "malshare"]

    def get(name):
        if name == "malwarebazaar":
            return mb
        if name == "malshare":
            return ms
        raise KeyError(name)

    registry.get.side_effect = get
    return registry, mb, ms


def _active_benign_registry(sys_discover, gh_discover, bn_discover=None):
    sysinternals = MagicMock()
    sysinternals.name = "sysinternals"
    sysinternals.expected_label = 0
    sysinternals.discover.side_effect = sys_discover

    github = MagicMock()
    github.name = "github"
    github.expected_label = 0
    github.discover.side_effect = gh_discover

    benign_net = MagicMock()
    benign_net.name = "benign_net"
    benign_net.expected_label = 0
    benign_net.discover.side_effect = bn_discover or (lambda _limit: [])

    registry = MagicMock()
    registry.list_names.return_value = ["sysinternals", "github", "benign_net"]

    def get(name):
        if name == "sysinternals":
            return sysinternals
        if name == "github":
            return github
        if name == "benign_net":
            return benign_net
        raise KeyError(name)

    registry.get.side_effect = get
    return registry, sysinternals, github, benign_net


def _tracker():
    tracker = MagicMock()
    tracker.is_downloaded.return_value = False
    tracker.is_corrupted.return_value = False
    tracker.is_pending.return_value = False
    tracker.is_source_url_seen.return_value = False
    return tracker


def test_active_malware_sources_split_between_malwarebazaar_and_malshare(monkeypatch):
    monkeypatch.setenv("MALWAREBAZAAR_AUTH_KEY", "test-key")
    monkeypatch.setattr("src.config.MALSHARE_ENABLED", True)
    registry, mb, ms = _active_registry(
        mb_discover=lambda _limit: [
            _candidate("a", "malwarebazaar"),
            _candidate("b", "malwarebazaar"),
            _candidate("c", "malwarebazaar"),
        ],
        ms_discover=lambda _limit: [
            _candidate("d", "malshare"),
            _candidate("e", "malshare"),
        ],
    )
    stats: list[dict] = []
    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)

    out = discover_active_malware_sources(
        ["malwarebazaar"],
        registry=registry,
        tracker=_tracker(),
        ctx=ctx,
        limit=5,
        stats=stats,
    )

    assert [candidate.provider for candidate in out] == [
        "malwarebazaar",
        "malwarebazaar",
        "malwarebazaar",
        "malshare",
        "malshare",
    ]
    mb.discover.assert_called_once_with(15)
    ms.discover.assert_called_once_with(10)
    assert [item["provider"] for item in stats[:2]] == ["malwarebazaar", "malshare"]


@patch("src.collection.discovery_chain.discover_with_fallback")
def test_active_malware_sources_disabled_uses_existing_chain(mock_discover, monkeypatch):
    monkeypatch.setenv("MALWAREBAZAAR_AUTH_KEY", "test-key")
    monkeypatch.setattr("src.config.MALSHARE_ENABLED", False)
    mock_discover.return_value = [_candidate("a", "malwarebazaar")]
    registry, _mb, _ms = _active_registry(lambda _limit: [], lambda _limit: [])
    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)

    out = discover_active_malware_sources(
        ["malwarebazaar"],
        registry=registry,
        tracker=_tracker(),
        ctx=ctx,
        limit=5,
    )

    assert len(out) == 1
    mock_discover.assert_called_once()
    assert mock_discover.call_args.args[0] == ["malwarebazaar"]


def test_active_malware_sources_deduplicates_malshare_overlap(monkeypatch):
    monkeypatch.setenv("MALWAREBAZAAR_AUTH_KEY", "test-key")
    monkeypatch.setattr("src.config.MALSHARE_ENABLED", True)
    same = SampleCandidate("a" * 64, "malwarebazaar", 1, {"sha256": "a" * 64})
    overlap = SampleCandidate("a" * 64, "malshare", 1, {"sha256": "a" * 64})
    registry, _mb, _ms = _active_registry(
        mb_discover=lambda _limit: [same],
        ms_discover=lambda _limit: [overlap],
    )
    ctx = CollectionContext(benign_count=0, malware_count=0, model_ready=False, pending_depth=0)

    out = discover_active_malware_sources(
        ["malwarebazaar"],
        registry=registry,
        tracker=_tracker(),
        ctx=ctx,
        limit=2,
    )

    assert len(out) == 1
    assert out[0].provider == "malwarebazaar"


def test_active_benign_sources_split_across_selected_providers():
    from src.collection.discovery_chain import discover_active_benign_sources

    registry, sysinternals, github, benign_net = _active_benign_registry(
        sys_discover=lambda _limit: [
            SampleCandidate("s1", "sysinternals", 0, {"url": "https://s/1.exe"}),
            SampleCandidate("s2", "sysinternals", 0, {"url": "https://s/2.exe"}),
        ],
        gh_discover=lambda _limit: [
            SampleCandidate("g1", "github", 0, {"url": "https://g/1.exe"}),
            SampleCandidate("g2", "github", 0, {"url": "https://g/2.exe"}),
        ],
        bn_discover=lambda _limit: [
            SampleCandidate("b1", "benign_net", 0, {"path": "/repo/b1.exe"}),
            SampleCandidate("b2", "benign_net", 0, {"path": "/repo/b2.exe"}),
        ],
    )
    ctx = CollectionContext(benign_count=100, malware_count=100, model_ready=True, pending_depth=0)
    stats: list[dict] = []

    out = discover_active_benign_sources(
        ["sysinternals", "github", "benign_net"],
        registry=registry,
        tracker=_tracker(),
        ctx=ctx,
        limit=6,
        stats=stats,
    )

    assert [candidate.provider for candidate in out] == [
        "sysinternals",
        "sysinternals",
        "github",
        "github",
        "benign_net",
        "benign_net",
    ]
    sysinternals.discover.assert_called_once_with(10)
    github.discover.assert_called_once_with(10)
    benign_net.discover.assert_called_once_with(10)
    assert [item["provider"] for item in stats[:3]] == [
        "sysinternals",
        "github",
        "benign_net",
    ]


def test_malwarebazaar_empty_continues_fallbacks_until_limit(monkeypatch):
    _use_legacy_malware_fallback_chain(monkeypatch)
    sha = "x" * 64
    registry, mb, tf, tw, otx = _make_registry(
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


def test_malwarebazaar_full_batch_does_not_call_fallbacks():
    registry, _mb, tf, tw, otx = _make_registry(
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
    otx.discover.assert_not_called()


def test_partial_batches_fill_from_fallbacks(monkeypatch):
    _use_legacy_malware_fallback_chain(monkeypatch)
    registry, _mb, _tf, tw, otx = _make_registry(
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
    otx.discover.assert_not_called()


def test_malwarebazaar_empty_uses_twitter_before_otx(monkeypatch):
    _use_legacy_malware_fallback_chain(monkeypatch)
    sha = "t" * 64
    registry, _mb, _tf, tw, otx = _make_registry(
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
    otx.discover.assert_called_once()


def test_all_empty_falls_back_to_otx_pulse_cti(monkeypatch):
    _use_legacy_malware_fallback_chain(monkeypatch)
    sha = "y" * 64
    registry, _mb, _tf, _tw, otx = _make_registry(
        mb_discover=lambda _limit: [],
        tf_discover=lambda _limit: [],
        tw_discover=lambda _limit: [],
        otx_discover=lambda _limit: [SampleCandidate(sha, "otx_pulse_cti", 1, {"sha256": sha})],
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
    assert out[0].provider == "otx_pulse_cti"


def test_configured_fallback_chain_can_skip_low_yield_providers(monkeypatch):
    monkeypatch.setattr("src.collection.discovery_chain.MALWARE_FALLBACK_PROVIDERS", ("threatfox",))
    registry, _mb, tf, tw, otx = _make_registry(
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
    otx.discover.assert_not_called()


def test_otx_fallback_when_ctx_none(monkeypatch):
    _use_legacy_malware_fallback_chain(monkeypatch)
    sha = "z" * 64
    registry, _mb, _tf, _tw, otx = _make_registry(
        mb_discover=lambda _limit: [],
        tf_discover=lambda _limit: [],
        tw_discover=lambda _limit: [],
        otx_discover=lambda _limit: [SampleCandidate(sha, "otx_pulse_cti", 1, {"sha256": sha})],
    )

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
    assert out[0].provider == "otx_pulse_cti"

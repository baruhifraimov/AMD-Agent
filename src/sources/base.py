"""Abstract PE sample source providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class SampleCandidate:
    """A discoverable PE sample from an external source."""

    external_id: str
    provider: str
    expected_label: int
    download_ref: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SampleCandidate:
        return cls(
            external_id=data["external_id"],
            provider=data["provider"],
            expected_label=int(data["expected_label"]),
            download_ref=dict(data.get("download_ref") or {}),
            metadata=dict(data.get("metadata") or {}),
        )


class PESourceProvider(ABC):
    """Strategy interface for discovering and downloading PE binaries."""

    name: str
    expected_label: int

    @abstractmethod
    def discover(self, limit: int) -> list[SampleCandidate]:
        """Return up to `limit` candidates without downloading."""

    @abstractmethod
    def download(self, candidate: SampleCandidate) -> bytes:
        """Download raw PE bytes for a discovered candidate."""

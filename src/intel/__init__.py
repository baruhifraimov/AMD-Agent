"""In-process threat intelligence collection and source registry."""


def __getattr__(name: str):
    if name == "ThreatIntelCollector":
        from src.intel.collector import ThreatIntelCollector

        return ThreatIntelCollector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["ThreatIntelCollector"]

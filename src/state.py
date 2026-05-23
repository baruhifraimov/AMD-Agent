"""Shared Pydantic state for the agent graph."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AgentState(BaseModel):
    discovered_hashes: List[str] = Field(default_factory=list)
    downloaded_paths: List[str] = Field(default_factory=list)
    feature_vectors: List[Dict[str, Any]] = Field(default_factory=list)
    feature_errors: Dict[str, str] = Field(default_factory=dict)
    predictions: Dict[str, float] = Field(default_factory=dict)
    drift_detected: bool = False
    new_labeled_batch: List[Dict[str, Any]] = Field(default_factory=list)
    evaluation_metrics: Dict[str, float] = Field(default_factory=dict)
    semantic_report: Optional[str] = None

    source_type: str = ""
    selected_sources: List[str] = Field(default_factory=list)
    collection_phase: str = ""
    route_hint: str = ""
    discovery_strategy: str = ""
    cti_evidence: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    expected_label: int = 1
    sample_candidates: List[Dict[str, Any]] = Field(default_factory=list)
    rejected_candidates: List[Dict[str, Any]] = Field(default_factory=list)
    capa_results: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    hash_metadata: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    section_entropies: List[float] = Field(default_factory=list)
    intel_poll_stats: Dict[str, Any] = Field(default_factory=dict)
    intel_sources_polled: List[str] = Field(default_factory=list)
    bootstrap_metrics: Dict[str, Any] = Field(default_factory=dict)

    drift_stats: Dict[str, float] = Field(default_factory=dict)
    drift_pre_metrics: Dict[str, float] = Field(default_factory=dict)
    pending_drift_log: bool = False
    need_new_sources: bool = False

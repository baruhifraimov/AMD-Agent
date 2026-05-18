"""Shared Pydantic state for the agent graph."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AgentState(BaseModel):
    discovered_hashes: List[str] = Field(default_factory=list)
    downloaded_paths: List[str] = Field(default_factory=list)
    feature_vectors: List[Dict[str, Any]] = Field(default_factory=list)
    predictions: Dict[str, float] = Field(default_factory=dict)
    drift_detected: bool = False
    new_labeled_batch: List[Dict[str, Any]] = Field(default_factory=list)
    evaluation_metrics: Dict[str, float] = Field(default_factory=dict)
    semantic_report: Optional[str] = None

    source_type: str = ""
    expected_label: int = 1
    sample_candidates: List[Dict[str, Any]] = Field(default_factory=list)

    hash_metadata: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    section_entropies: List[float] = Field(default_factory=list)

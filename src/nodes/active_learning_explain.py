"""Active learning explain node (stub — LLM/capa disabled in v1)."""

from src.state import AgentState


def active_learning_explain(state: AgentState) -> dict:
    entropies = state.section_entropies
    avg_ent = sum(entropies) / len(entropies) if entropies else 0.0
    report = (
        "Drift detected; LLM/capa disabled in v1. "
        f"Batch size={len(state.new_labeled_batch)}, "
        f"mean section entropy={avg_ent:.4f}. "
        "Recommend manual review of anomalous PE imports and section layout."
    )
    return {"semantic_report": report}

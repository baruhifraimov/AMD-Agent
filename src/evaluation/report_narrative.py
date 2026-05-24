"""Generate narrative report observations from evaluation logs."""

from __future__ import annotations

import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import src.config as cfg
from src.evaluation.report_figures import (
    _load_drift_events,
    _load_retrain_events,
    read_jsonl,
)


def _pp(value: float) -> str:
    return f"{value * 100:.1f} pp"


def _fmt(value: float) -> str:
    return f"{value:.4f}"


def _might_warn(count: int, label: str) -> str:
    if count == 0:
        return f"**Warning:** No {label} — run bootstrap/daemon to accumulate data.\n"
    return ""


def analyze_performance_decay(eval_path: Path | None = None) -> dict[str, Any]:
    eval_path = eval_path or cfg.EVAL_LOG_PATH
    records = read_jsonl(eval_path)
    records.sort(key=lambda r: r.get("timestamp", ""))
    accs: list[float] = []
    fprs: list[float] = []
    timestamps: list[str] = []
    for rec in records:
        m = rec.get("metrics", {})
        if "accuracy" in m:
            accs.append(float(m["accuracy"]))
            fprs.append(float(m.get("fpr", 0.0)))
            timestamps.append(str(rec.get("timestamp", "")))

    if not accs:
        return {"count": 0, "summary": "No evaluation snapshots recorded.", "caption": ""}

    min_acc, max_acc = min(accs), max(accs)
    min_idx = accs.index(min_acc)
    max_idx = accs.index(max_acc)
    largest_drop = 0.0
    drop_from = drop_to = ""
    for i in range(1, len(accs)):
        delta = accs[i] - accs[i - 1]
        if delta < largest_drop:
            largest_drop = delta
            drop_from = timestamps[i - 1][:16]
            drop_to = timestamps[i][:16]

    recovery = ""
    if largest_drop < 0 and min_idx < len(accs) - 1:
        post_min_best = max(accs[min_idx:])
        recovery = f"; recovered {_pp(post_min_best - min_acc)} after low at {timestamps[min_idx][:16]}"

    mean_fpr = sum(fprs) / len(fprs) if fprs else 0.0
    summary = (
        f"Accuracy ranged {_fmt(min_acc)}–{_fmt(max_acc)} across {len(accs)} snapshots "
        f"(peak {timestamps[max_idx][:16]}, low {timestamps[min_idx][:16]})."
    )
    if largest_drop < 0:
        summary += f" Largest drop {_pp(largest_drop)} between {drop_from} and {drop_to}{recovery}."
    summary += f" Mean FPR {_fmt(mean_fpr)}."

    caption = (
        f"Figure 4: Holdout accuracy (blue) and FPR (red) over {len(accs)} chronological "
        f"TESSERACT snapshots. {summary}"
    )
    return {
        "count": len(accs),
        "min_acc": min_acc,
        "max_acc": max_acc,
        "largest_drop_pp": largest_drop * 100,
        "mean_fpr": mean_fpr,
        "summary": summary,
        "caption": caption,
    }


def analyze_retrain_delta(
    model_update_path: Path | None = None,
    training_history_path: Path | None = None,
) -> dict[str, Any]:
    events = _load_retrain_events(model_update_path, training_history_path)
    if not events:
        return {"count": 0, "summary": "No holdout pre/post retrain comparisons.", "caption": ""}

    acc_deltas = [e["post_acc"] - e["prev_acc"] for e in events]
    fpr_deltas = [e["post_fpr"] - e["prev_fpr"] for e in events]
    mean_acc_delta = sum(acc_deltas) / len(acc_deltas)
    last = events[-1]
    summary = (
        f"{len(events)} holdout comparisons; mean accuracy gain {_pp(mean_acc_delta)}; "
        f"mean FPR change {_pp(sum(fpr_deltas) / len(fpr_deltas))}. "
        f"Latest ({last['ts']}): accuracy {_fmt(last['prev_acc'])}→{_fmt(last['post_acc'])} "
        f"({_pp(last['post_acc'] - last['prev_acc'])}), FPR {_fmt(last['prev_fpr'])}→{_fmt(last['post_fpr'])}."
    )
    caption = (
        f"Figure 5: Pre- vs post-retraining holdout metrics from model_update_log.jsonl. {summary}"
    )
    return {"count": len(events), "mean_acc_delta_pp": mean_acc_delta * 100, "summary": summary, "caption": caption}


def analyze_drift_delta(drift_path: Path | None = None) -> dict[str, Any]:
    drift_path = drift_path or cfg.DRIFT_LOG_PATH
    raw_events = read_jsonl(drift_path)
    events = _load_drift_events(drift_path)
    if not events:
        if raw_events:
            summary = (
                f"{len(raw_events)} drift event(s) logged but pre/post TESSERACT metrics were empty; "
                "re-run pipeline after evaluation_node fix to populate metrics."
            )
        else:
            summary = "No drift pre/post metric pairs."
        return {"count": len(events), "raw_count": len(raw_events), "summary": summary, "caption": ""}

    acc_deltas = [e["delta_acc"] for e in events]
    mean_delta = sum(acc_deltas) / len(acc_deltas)
    improved = sum(1 for d in acc_deltas if d >= 0)
    summary = (
        f"{len(events)} concept-drift events; {improved}/{len(events)} with non-negative accuracy delta; "
        f"mean post-retrain accuracy change {_pp(mean_delta)}."
    )
    caption = f"Figure 5b: Drift-time TESSERACT metrics before vs after retraining. {summary}"
    return {"count": len(events), "mean_acc_delta_pp": mean_delta * 100, "summary": summary, "caption": caption}


def analyze_source_provenance(db_path: Path | None = None) -> dict[str, Any]:
    db_path = db_path or cfg.DB_PATH
    if not db_path.exists():
        return {"count": 0, "summary": "No SQLite database.", "caption": ""}

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        """
        SELECT COALESCE(NULLIF(source_provider, ''), 'unknown') AS provider,
               label,
               COUNT(*) AS n
        FROM samples
        WHERE status = 'active'
        GROUP BY provider, label
        """
    ).fetchall()
    days = conn.execute(
        """
        SELECT COUNT(DISTINCT date(COALESCE(NULLIF(ingested_at, ''), acquired_at)))
        FROM samples WHERE status = 'active'
        """
    ).fetchone()
    conn.close()

    total = sum(r[2] for r in rows)
    if total == 0:
        return {"count": 0, "summary": "No active samples.", "caption": ""}

    by_provider: Counter[str] = Counter()
    for provider, _label, n in rows:
        by_provider[provider] += n
    top = by_provider.most_common(5)
    top_str = ", ".join(f"{name} ({count})" for name, count in top)
    n_providers = len(by_provider)
    n_days = int(days[0] or 0) if days else 0

    summary = (
        f"{total} active samples across {n_providers} providers over {n_days} ingest day(s). "
        f"Top sources: {top_str}."
    )
    caption = f"Figure 6: Source provenance evolution by ingest day. {summary}"
    return {
        "count": total,
        "providers": n_providers,
        "summary": summary,
        "caption": caption,
    }


def analyze_madar_composition(training_history_path: Path | None = None) -> dict[str, Any]:
    training_history_path = training_history_path or cfg.TRAINING_HISTORY_PATH
    rows: list[tuple[float, float]] = []
    for rec in read_jsonl(training_history_path):
        replay = rec.get("madar_replay_selected")
        if replay is None:
            replay = rec.get("replay_size")
        new_batch = rec.get("sample_count")
        if new_batch is None:
            new_batch = rec.get("new_batch_size")
        if replay is None and new_batch is None:
            continue
        rows.append((float(replay or 0), float(new_batch or 0)))

    if not rows:
        return {"count": 0, "summary": "No MADAR replay composition logged.", "caption": ""}

    replays = [r[0] for r in rows]
    new_batches = [r[1] for r in rows]
    mean_replay = sum(replays) / len(replays)
    mean_new = sum(new_batches) / len(new_batches)
    has_replay_field = any(r > 0 for r in replays)
    replay_note = "" if has_replay_field else " (replay counts use legacy pool size until next retrain)"
    summary = (
        f"{len(rows)} retrain record(s); mean replay {mean_replay:.0f} samples, "
        f"mean new batch {mean_new:.0f} samples{replay_note}."
    )
    caption = f"Figure 7b: MADAR replay vs new batch composition per retrain. {summary}"
    return {"count": len(rows), "summary": summary, "caption": caption}


def build_report_markdown(analyses: dict[str, dict[str, Any]] | None = None) -> str:
    if analyses is None:
        analyses = {
            "decay": analyze_performance_decay(),
            "retrain": analyze_retrain_delta(),
            "drift": analyze_drift_delta(),
            "provenance": analyze_source_provenance(),
            "madar": analyze_madar_composition(),
        }

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# AMD-Agent Report — Observations",
        "",
        f"_Generated {generated} from logs under `data/` and SQLite._",
        "",
        "Regenerate: `python scripts/generate_report_figures.py`",
        "",
        "---",
        "",
        "## Figure 4 — TESSERACT temporal performance",
        "",
        _might_warn(analyses["decay"]["count"], "evaluation_log.jsonl entries"),
        f"**Observation:** {analyses['decay']['summary']}",
        "",
        f"**Caption:** {analyses['decay']['caption']}",
        "",
        "**Artifact:** `report/figures/performance_decay.png`",
        "",
        "---",
        "",
        "## Figure 5 — Pre/post retraining (holdout)",
        "",
        _might_warn(analyses["retrain"]["count"], "model update comparisons"),
        f"**Observation:** {analyses['retrain']['summary']}",
        "",
        f"**Caption:** {analyses['retrain']['caption']}",
        "",
        "**Artifact:** `report/figures/retrain_pre_post_delta.png`",
        "",
        "---",
        "",
        "## Figure 5b — Concept drift pre/post metrics",
        "",
        _might_warn(analyses["drift"]["count"], "drift events with pre/post metrics"),
        f"**Observation:** {analyses['drift']['summary']}",
        "",
        f"**Caption:** {analyses['drift']['caption']}",
        "",
        "**Artifact:** `report/figures/drift_pre_post_delta.png`",
        "",
        "---",
        "",
        "## Figure 6 — Source provenance evolution",
        "",
        _might_warn(analyses["provenance"]["count"], "active SQLite samples"),
        f"**Observation:** {analyses['provenance']['summary']}",
        "",
        f"**Caption:** {analyses['provenance']['caption']}",
        "",
        "**Artifact:** `report/figures/source_provenance_evolution.png`",
        "",
        "---",
        "",
        "## Figure 7b — MADAR replay composition",
        "",
        _might_warn(analyses["madar"]["count"], "MADAR replay records"),
        f"**Observation:** {analyses['madar']['summary']}",
        "",
        f"**Caption:** {analyses['madar']['caption']}",
        "",
        "**Artifact:** `report/figures/madar_replay_composition.png`",
        "",
        "---",
        "",
        "## Architecture figures (manual export)",
        "",
        "Export `report/diagrams/*.mmd` via [Mermaid Live](https://mermaid.live) to SVG/PNG.",
        "Static captions and checklist: `report/FIGURES.md`.",
        "",
    ]
    return "\n".join(lines)


def write_report_narrative(
    path: Path | None = None,
    *,
    analyses: dict[str, dict[str, Any]] | None = None,
) -> Path:
    cfg.ensure_dirs()
    path = path or cfg.REPORT_NARRATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_report_markdown(analyses), encoding="utf-8")
    return path

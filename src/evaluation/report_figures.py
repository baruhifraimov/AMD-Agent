"""Generate matplotlib report figures from JSONL logs and SQLite."""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any

import src.config as cfg
from src.evaluation.report_style import (
    COLOR_ACCURACY,
    COLOR_BENIGN,
    COLOR_FPR,
    COLOR_MALWARE,
    FIGURE_DPI,
)

METRIC_KEYS = ("accuracy", "precision", "recall", "fpr", "tpr")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def backfill_eval_log_from_training_history(
    *,
    eval_path: Path | None = None,
    hist_path: Path | None = None,
    min_rows: int = 5,
    run_live_eval: bool = True,
) -> int:
    """Append training_history snapshots to evaluation_log when periodic eval is sparse."""
    eval_path = eval_path or cfg.EVAL_LOG_PATH
    hist_path = hist_path or cfg.TRAINING_HISTORY_PATH
    if not hist_path.exists():
        return 0

    existing_ts: set[str] = set()
    for rec in read_jsonl(eval_path):
        existing_ts.add(str(rec.get("timestamp", "")))

    added = 0
    eval_path.parent.mkdir(parents=True, exist_ok=True)
    with eval_path.open("a", encoding="utf-8") as out:
        for rec in read_jsonl(hist_path):
            ts = str(rec.get("timestamp", ""))
            if not ts or ts in existing_ts:
                continue
            metrics = rec.get("metrics") or {}
            if "accuracy" not in metrics:
                continue
            row = {
                "timestamp": ts,
                "trigger": rec.get("trigger") or "retrain_eval",
                "model_version": rec.get("model_version", ""),
                "retrain_count": int(rec.get("retrain_count", 0) or 0),
                "metrics": {
                    k: float(v) for k, v in metrics.items() if isinstance(v, (int, float))
                },
            }
            out.write(json.dumps(row) + "\n")
            existing_ts.add(ts)
            added += 1

    total = len(read_jsonl(eval_path))
    if run_live_eval and total < min_rows:
        try:
            from src.evaluation.tesseract import append_eval_log, run_tesseract_eval

            metrics = run_tesseract_eval()
            if metrics:
                append_eval_log(metrics, path=eval_path)
                added += 1
        except Exception:
            pass
    return added


def _metric_delta(
    previous: dict[str, float],
    updated: dict[str, float],
    keys: tuple[str, ...] = METRIC_KEYS,
) -> dict[str, float]:
    return {
        key: float(updated[key] - previous[key])
        for key in keys
        if key in previous and key in updated
    }


def _load_retrain_events(
    model_update_path: Path | None = None,
    training_history_path: Path | None = None,
) -> list[dict[str, Any]]:
    model_update_path = model_update_path or cfg.MODEL_UPDATE_LOG_PATH
    training_history_path = training_history_path or cfg.TRAINING_HISTORY_PATH
    events: list[dict[str, Any]] = []
    for rec in read_jsonl(model_update_path):
        if rec.get("status") == "baseline_created":
            continue
        prev = rec.get("previous_metrics") or {}
        post = rec.get("updated_metrics") or {}
        if prev and post:
            events.append(
                {
                    "ts": (rec.get("timestamp") or "")[:16],
                    "trigger": rec.get("trigger", ""),
                    "prev_acc": float(prev.get("accuracy", 0)),
                    "post_acc": float(post.get("accuracy", 0)),
                    "prev_fpr": float(prev.get("fpr", 0)),
                    "post_fpr": float(post.get("fpr", 0)),
                }
            )
    if events:
        return events

    for rec in read_jsonl(training_history_path):
        prev = rec.get("previous") or {}
        cur = rec.get("metrics") or {}
        if prev and cur and "accuracy" in cur:
            events.append(
                {
                    "ts": (rec.get("timestamp") or "")[:16],
                    "trigger": rec.get("trigger", "retrain"),
                    "prev_acc": float(prev.get("accuracy", 0)),
                    "post_acc": float(cur.get("accuracy", 0)),
                    "prev_fpr": float(prev.get("fpr", 0)),
                    "post_fpr": float(cur.get("fpr", 0)),
                }
            )
    return events


def _load_drift_events(drift_path: Path | None = None) -> list[dict[str, Any]]:
    drift_path = drift_path or cfg.DRIFT_LOG_PATH
    events: list[dict[str, Any]] = []
    for rec in read_jsonl(drift_path):
        pre = rec.get("pre_metrics") or {}
        post = rec.get("post_metrics") or {}
        if not pre or not post:
            continue
        delta = rec.get("delta_metrics") or _metric_delta(pre, post)
        events.append(
            {
                "ts": (rec.get("timestamp") or "")[:16],
                "pre_acc": float(pre.get("accuracy", 0)),
                "post_acc": float(post.get("accuracy", 0)),
                "pre_fpr": float(pre.get("fpr", 0)),
                "post_fpr": float(post.get("fpr", 0)),
                "delta_acc": float(delta.get("accuracy", post.get("accuracy", 0) - pre.get("accuracy", 0))),
            }
        )
    return events


def _event_markers(
    eval_records: list[dict[str, Any]],
    *,
    drift_path: Path | None = None,
    training_history_path: Path | None = None,
) -> list[tuple[int, str, str]]:
    """Map drift/retrain timestamps to nearest eval snapshot index (1-based)."""
    if not eval_records:
        return []
    eval_ts = [str(r.get("timestamp", "")) for r in eval_records]
    markers: list[tuple[int, str, str]] = []

    def nearest_index(ts: str) -> int | None:
        if not ts or not eval_ts:
            return None
        for i, e_ts in enumerate(eval_ts):
            if e_ts >= ts:
                return i + 1
        return len(eval_ts)

    for rec in read_jsonl(drift_path or cfg.DRIFT_LOG_PATH):
        ts = str(rec.get("timestamp", ""))
        idx = nearest_index(ts)
        if idx:
            markers.append((idx, "drift", ts[:16]))

    for rec in read_jsonl(training_history_path or cfg.TRAINING_HISTORY_PATH):
        ts = str(rec.get("timestamp", ""))
        idx = nearest_index(ts)
        if idx:
            markers.append((idx, "retrain", ts[:16]))
    return markers


def plot_performance_decay(
    out_dir: Path | None = None,
    *,
    eval_path: Path | None = None,
    drift_path: Path | None = None,
    training_history_path: Path | None = None,
    mirror_legacy: bool = True,
) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out_dir = out_dir or cfg.FIGURES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "performance_decay.png"
    eval_path = eval_path or cfg.EVAL_LOG_PATH

    records = read_jsonl(eval_path)
    records.sort(key=lambda r: r.get("timestamp", ""))

    if not records:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.text(0.5, 0.5, "No evaluation_log.jsonl", ha="center", va="center")
        fig.savefig(out_path, dpi=FIGURE_DPI)
        plt.close(fig)
        return out_path

    accs, fprs = [], []
    for rec in records:
        m = rec.get("metrics", {})
        if "accuracy" in m:
            accs.append(float(m["accuracy"]))
        if "fpr" in m:
            fprs.append(float(m["fpr"]))

    fig, ax1 = plt.subplots(figsize=(10, 5))
    runs = list(range(1, len(accs) + 1))
    if accs:
        ax1.plot(runs, accs, color=COLOR_ACCURACY, marker="o", linewidth=2, label="Accuracy")
    ax1.set_xlabel("Evaluation snapshot (chronological)")
    ax1.set_ylabel("Accuracy", color=COLOR_ACCURACY)
    ax1.set_title("TESSERACT temporal performance")
    ax1.set_ylim(0, 1.05)
    ax1.grid(True, alpha=0.3)

    if fprs and len(fprs) == len(accs):
        ax2 = ax1.twinx()
        ax2.plot(runs, fprs, color=COLOR_FPR, marker="s", linestyle="--", linewidth=2, label="FPR")
        ax2.set_ylabel("FPR", color=COLOR_FPR)

    for idx, kind, ts in _event_markers(
        records, drift_path=drift_path, training_history_path=training_history_path
    ):
        color = COLOR_FPR if kind == "drift" else COLOR_BENIGN
        ax1.axvline(idx, color=color, linestyle=":", alpha=0.45, linewidth=1.2)
        ax1.text(idx, 1.02, kind[0].upper(), ha="center", fontsize=7, color=color)

    fig.tight_layout()
    fig.savefig(out_path, dpi=FIGURE_DPI)
    plt.close(fig)

    if mirror_legacy:
        legacy = cfg.LEGACY_FIGURES_DIR / "performance_decay.png"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(out_path, legacy)
    return out_path


def plot_source_provenance(
    out_dir: Path | None = None,
    *,
    db_path: Path | None = None,
) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    out_dir = out_dir or cfg.FIGURES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "source_provenance_evolution.png"
    db_path = db_path or cfg.DB_PATH

    if not db_path.exists():
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.text(0.5, 0.5, "No malware_tracker.db", ha="center", va="center")
        fig.savefig(out_path, dpi=FIGURE_DPI)
        plt.close(fig)
        return out_path

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        """
        SELECT date(COALESCE(NULLIF(ingested_at, ''), acquired_at)) AS day,
               COALESCE(NULLIF(source_provider, ''), 'unknown') AS provider,
               label,
               COUNT(*) AS n
        FROM samples
        WHERE status = 'active'
        GROUP BY day, provider, label
        ORDER BY day, provider
        """
    ).fetchall()
    conn.close()

    days = sorted({r[0] for r in rows if r[0]})
    providers = sorted({r[1] for r in rows})
    if not days:
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.text(0.5, 0.5, "No active samples", ha="center", va="center")
        fig.savefig(out_path, dpi=FIGURE_DPI)
        plt.close(fig)
        return out_path

    mal_counts: dict[str, list[float]] = {p: [] for p in providers}
    ben_counts: dict[str, list[float]] = {p: [] for p in providers}
    for day in days:
        for p in providers:
            mal_counts[p].append(
                sum(r[3] for r in rows if r[0] == day and r[1] == p and r[2] == 1)
            )
            ben_counts[p].append(
                sum(r[3] for r in rows if r[0] == day and r[1] == p and r[2] == 0)
            )

    fig, ax = plt.subplots(figsize=(11, 5))
    x = np.arange(len(days))
    bottom_m = np.zeros(len(days))
    bottom_b = np.zeros(len(days))
    for i, p in enumerate(providers):
        m = np.array(mal_counts[p], dtype=float)
        b = np.array(ben_counts[p], dtype=float)
        if m.sum() > 0:
            ax.bar(
                x,
                m,
                bottom=bottom_m,
                label=f"{p} (malware)",
                color=COLOR_MALWARE,
                alpha=0.55 + 0.35 * (i / max(len(providers), 1)),
                edgecolor="white",
                linewidth=0.3,
            )
            bottom_m += m
        if b.sum() > 0:
            ax.bar(
                x,
                b,
                bottom=bottom_b,
                label=f"{p} (benign)",
                color=COLOR_BENIGN,
                alpha=0.55 + 0.35 * (i / max(len(providers), 1)),
                edgecolor="white",
                linewidth=0.3,
            )
            bottom_b += b

    ax.set_xticks(x)
    ax.set_xticklabels(days, rotation=25, ha="right")
    ax.set_ylabel("Active samples ingested")
    ax.set_title("Source provenance evolution (by ingest day)")
    ax.legend(loc="upper left", fontsize=7, ncol=2)
    fig.tight_layout()
    fig.savefig(out_path, dpi=FIGURE_DPI)
    plt.close(fig)
    return out_path


def plot_retrain_delta_bars(
    out_dir: Path | None = None,
    *,
    model_update_path: Path | None = None,
    training_history_path: Path | None = None,
) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    out_dir = out_dir or cfg.FIGURES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "retrain_pre_post_delta.png"
    events = _load_retrain_events(model_update_path, training_history_path)

    if not events:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.text(0.5, 0.5, "No pre/post retrain metrics", ha="center", va="center")
        fig.savefig(out_path, dpi=FIGURE_DPI)
        plt.close(fig)
        return out_path

    events = events[-8:]
    labels = [f"{e['ts']}\n{e['trigger'][:12]}" for e in events]
    x = np.arange(len(events))
    width = 0.35

    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar(x - width / 2, [e["prev_acc"] for e in events], width, label="Pre accuracy", color="#90CAF9")
    ax.bar(x + width / 2, [e["post_acc"] for e in events], width, label="Post accuracy", color=COLOR_BENIGN)
    ax.set_ylabel("Holdout accuracy")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7)
    ax.set_ylim(0, 1.05)
    ax.set_title("Pre- vs post-retraining holdout metrics")
    ax.grid(True, axis="y", alpha=0.3)

    ax2 = ax.twinx()
    ax2.plot(x, [e["prev_fpr"] for e in events], color=COLOR_FPR, marker="o", linestyle="--", label="Pre FPR")
    ax2.plot(x, [e["post_fpr"] for e in events], color="#EF5350", marker="s", label="Post FPR")
    ax2.set_ylabel("FPR", color=COLOR_FPR)
    lines1, lab1 = ax.get_legend_handles_labels()
    lines2, lab2 = ax2.get_legend_handles_labels()
    ax.legend(lines1 + lines2, lab1 + lab2, loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path, dpi=FIGURE_DPI)
    plt.close(fig)
    return out_path


def plot_drift_pre_post_delta(
    out_dir: Path | None = None,
    *,
    drift_path: Path | None = None,
) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    out_dir = out_dir or cfg.FIGURES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "drift_pre_post_delta.png"
    events = _load_drift_events(drift_path)

    if not events:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.text(0.5, 0.5, "No drift pre/post metrics", ha="center", va="center")
        fig.savefig(out_path, dpi=FIGURE_DPI)
        plt.close(fig)
        return out_path

    events = events[-8:]
    labels = [e["ts"] for e in events]
    x = np.arange(len(events))
    width = 0.35

    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar(x - width / 2, [e["pre_acc"] for e in events], width, label="Pre-drift accuracy", color="#90CAF9")
    ax.bar(x + width / 2, [e["post_acc"] for e in events], width, label="Post-retrain accuracy", color=COLOR_BENIGN)
    ax.set_ylabel("TESSERACT accuracy at drift time")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7, rotation=20, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_title("Concept drift: pre- vs post-retraining metrics")
    ax.grid(True, axis="y", alpha=0.3)

    ax2 = ax.twinx()
    ax2.bar(
        x,
        [e["delta_acc"] for e in events],
        width=0.15,
        color=COLOR_MALWARE,
        alpha=0.5,
        label="Accuracy delta",
    )
    ax2.set_ylabel("Accuracy delta", color=COLOR_MALWARE)
    lines1, lab1 = ax.get_legend_handles_labels()
    lines2, lab2 = ax2.get_legend_handles_labels()
    ax.legend(lines1 + lines2, lab1 + lab2, loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path, dpi=FIGURE_DPI)
    plt.close(fig)
    return out_path


def plot_madar_composition(
    out_dir: Path | None = None,
    *,
    training_history_path: Path | None = None,
) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    out_dir = out_dir or cfg.FIGURES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "madar_replay_composition.png"
    training_history_path = training_history_path or cfg.TRAINING_HISTORY_PATH

    rows: list[dict[str, Any]] = []
    for rec in read_jsonl(training_history_path):
        replay = rec.get("madar_replay_selected")
        if replay is None:
            replay = rec.get("replay_size")
        new_batch = rec.get("sample_count")
        if new_batch is None:
            new_batch = rec.get("new_batch_size")
        if replay is None and new_batch is None:
            continue
        rows.append(
            {
                "ts": (rec.get("timestamp") or "")[:16],
                "replay": float(replay or 0),
                "new": float(new_batch or 0),
            }
        )

    if not rows:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.text(0.5, 0.5, "No MADAR replay history", ha="center", va="center")
        fig.savefig(out_path, dpi=FIGURE_DPI)
        plt.close(fig)
        return out_path

    rows = rows[-10:]
    labels = [r["ts"] for r in rows]
    x = np.arange(len(rows))
    replay = [r["replay"] for r in rows]
    new = [r["new"] for r in rows]

    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar(x, replay, label="MADAR replay selected", color=COLOR_BENIGN)
    ax.bar(x, new, bottom=replay, label="New drift batch", color=COLOR_MALWARE, alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7, rotation=20, ha="right")
    ax.set_ylabel("Training samples")
    ax.set_title("MADAR replay vs new batch per retrain")
    ax.legend()
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=FIGURE_DPI)
    plt.close(fig)
    return out_path


def plot_tool_registry_table(
    out_dir: Path | None = None,
    *,
    registry_md: Path | None = None,
) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out_dir = out_dir or cfg.FIGURES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "agent_tool_registry.png"
    registry_md = registry_md or (cfg.REPORT_DIR / "diagrams" / "03_agent_tool_registry.md")

    rows: list[list[str]] = []
    if registry_md.exists():
        for line in registry_md.read_text(encoding="utf-8").splitlines():
            if not line.startswith("|") or line.startswith("|-"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if cells and cells[0].lower() == "rubric tool":
                continue
            if len(cells) >= 4:
                rows.append(cells[:4])

    if not rows:
        rows = [
            ["Search", "cti_search.py", "is_public_url, fetch_public_text", "CTI discovery"],
            ["Fetch", "pe_download.py", "download_pe", "BinaryFetch"],
            ["Validate", "validate.py", "is_pe_mz, file_sha256", "DataValidation"],
            ["Update", "update.py", "insert_sample", "SQLite lifecycle"],
        ]

    fig, ax = plt.subplots(figsize=(12, 0.45 * len(rows) + 1.2))
    ax.axis("off")
    table = ax.table(
        cellText=rows,
        colLabels=["Tool", "Module", "Entry points", "Used by"],
        loc="center",
        cellLoc="left",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1, 1.4)
    ax.set_title("Reusable agent tools registry", fontsize=11, pad=12)
    fig.tight_layout()
    fig.savefig(out_path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(fig)
    return out_path


def generate_all_figures(
    out_dir: Path | None = None,
    *,
    backfill: bool = True,
    run_live_eval: bool = True,
) -> dict[str, Path]:
    """Regenerate all data-driven report figures."""
    cfg.ensure_dirs()
    out_dir = out_dir or cfg.FIGURES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    if backfill:
        backfill_eval_log_from_training_history(run_live_eval=run_live_eval)

    paths = {
        "performance_decay": plot_performance_decay(out_dir),
        "source_provenance": plot_source_provenance(out_dir),
        "retrain_pre_post_delta": plot_retrain_delta_bars(out_dir),
        "drift_pre_post_delta": plot_drift_pre_post_delta(out_dir),
        "madar_replay_composition": plot_madar_composition(out_dir),
        "agent_tool_registry": plot_tool_registry_table(out_dir),
    }
    return paths

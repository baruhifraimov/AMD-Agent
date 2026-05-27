#!/usr/bin/env python3
"""Generate academic-paper figures for AMD-Agent.

Outputs to report/figures/paper/:
  1. perf_over_time.png        — ML metrics across retrain events
  2. drift_per_session.png     — drift events per scheduled session
  3. data_per_source.png       — sample counts per provider (malware/benign split)
  4. agent_tool_usage.png      — LangGraph node activation counts
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.patches import Patch

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = ROOT / "report" / "figures" / "paper"
OUT.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA / "malware_tracker.db"
DRIFT_LOG = DATA / "drift_log.jsonl"
MODEL_LOG = DATA / "model_update_log.jsonl"
TRAIN_HIST = DATA / "training_history.jsonl"
EVAL_LOG = DATA / "evaluation_log.jsonl"
AGENT_LOG = DATA / "logs" / "amd-agent.log"

# Palette — colorblind-safe, paper-friendly
PALETTE = {
    "accuracy": "#1f77b4",
    "precision": "#2ca02c",
    "recall": "#ff7f0e",
    "fpr": "#d62728",
    "tpr": "#9467bd",
    "drift": "#C62828",
    "drift_cum": "#37474F",
    "malware": "#C62828",
    "benign": "#1565C0",
    "ml": "#1f77b4",
    "collection": "#2ca02c",
    "intel": "#ff7f0e",
    "infra": "#7f7f7f",
    "llm": "#9467bd",
}

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linestyle": "--",
    "figure.dpi": 110,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# -------------------------------------------------------------- 1. PERF OVER TIME

def fig_perf_over_time() -> Path:
    rows = _read_jsonl(MODEL_LOG)
    points = [r for r in rows if r.get("status") == "ok" and r.get("updated_metrics")]
    points.sort(key=lambda r: r["timestamp"])

    if not points:
        raise RuntimeError("no model_update_log rows with status=ok")

    ts = [_parse_ts(r["timestamp"]) for r in points]
    metrics = {k: [] for k in ("accuracy", "precision", "recall", "tpr", "fpr")}
    for r in points:
        m = r["updated_metrics"]
        for k in metrics:
            metrics[k].append(float(m.get(k, 0.0)))

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 6.5), sharex=True,
                                    gridspec_kw={"height_ratios": [3, 1]})

    # RECALL == TPR in binary classification; keep TPR only to avoid duplicate trace
    for k in ("accuracy", "precision", "tpr"):
        ax1.plot(ts, metrics[k], marker="o", markersize=4, linewidth=1.8,
                 color=PALETTE[k], label=k.upper())
    ax1.set_ylim(-0.02, 1.05)
    ax1.set_ylabel("Metric value")
    ax1.set_title("Model Performance Across Retrain Events")
    ax1.legend(loc="lower right", ncol=3, frameon=True, framealpha=0.9)

    ax2.plot(ts, metrics["fpr"], marker="s", markersize=4, linewidth=1.8,
             color=PALETTE["fpr"], label="FPR")
    ax2.fill_between(ts, 0, metrics["fpr"], color=PALETTE["fpr"], alpha=0.18)
    ax2.set_ylabel("FPR")
    ax2.set_xlabel("Retrain timestamp")
    ax2.set_ylim(-0.01, max(0.15, max(metrics["fpr"]) * 1.3))
    ax2.legend(loc="upper right", frameon=True, framealpha=0.9)

    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    fig.autofmt_xdate()

    out = OUT / "perf_over_time.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# -------------------------------------------------------------- 2. DRIFT PER SESSION

def fig_drift_per_session() -> Path:
    events = _read_jsonl(DRIFT_LOG)
    events.sort(key=lambda e: e["timestamp"])

    with sqlite3.connect(DB_PATH) as conn:
        tasks = conn.execute(
            "SELECT task_id, created_at, sample_count, trigger FROM task_log "
            "WHERE trigger = 'drift_detected' ORDER BY task_id"
        ).fetchall()

    if not tasks:
        raise RuntimeError("no drift_detected task_log rows")

    task_ids = [t[0] for t in tasks]
    sample_counts = [t[2] for t in tasks]
    mean_window = sum(sample_counts) / len(sample_counts)

    drift_ts = [_parse_ts(e["timestamp"]) for e in events]
    cum = list(range(1, len(drift_ts) + 1))

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 6.5),
                                    gridspec_kw={"height_ratios": [1.2, 1]})

    ax1.bar(task_ids, sample_counts, color=PALETTE["drift"], edgecolor="white",
            linewidth=0.6, label="drift window size")
    ax1.axhline(mean_window, color="#37474F", linestyle="--", linewidth=1.2,
                label=f"mean = {mean_window:.1f}")
    ax1.set_xlabel("Drift-triggered session (task_id)")
    ax1.set_ylabel("Samples in drift window")
    ax1.set_title("Drift-Triggered Retrain Sessions: Window Size per Session")
    ax1.set_xticks(task_ids[::2])
    ax1.legend(loc="upper right", frameon=True)

    ax2.plot(drift_ts, cum, marker="o", markersize=3, linewidth=2,
             color=PALETTE["drift_cum"])
    ax2.fill_between(drift_ts, 0, cum, color=PALETTE["drift_cum"], alpha=0.15)
    ax2.set_ylabel("Cumulative drift events")
    ax2.set_xlabel("Timestamp")
    ax2.set_title(f"Cumulative Drift Events (total = {len(events)})", fontsize=11)
    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    fig.autofmt_xdate()

    out = OUT / "drift_per_session.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# -------------------------------------------------------------- 3. DATA PER SOURCE

def fig_data_per_source() -> Path:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT source_provider, label, COUNT(*) FROM samples "
            "WHERE status='active' GROUP BY source_provider, label"
        ).fetchall()

    per_source: dict[str, dict[int, int]] = defaultdict(lambda: {0: 0, 1: 0})
    for prov, lab, cnt in rows:
        per_source[prov or "unknown"][int(lab)] = int(cnt)

    providers = sorted(per_source.keys(),
                       key=lambda p: -(per_source[p][0] + per_source[p][1]))
    benign = [per_source[p][0] for p in providers]
    malware = [per_source[p][1] for p in providers]
    totals = [b + m for b, m in zip(benign, malware)]

    fig, ax = plt.subplots(figsize=(10, 5.5))
    y = list(range(len(providers)))
    ax.barh(y, benign, color=PALETTE["benign"], label="Benign", edgecolor="white")
    ax.barh(y, malware, left=benign, color=PALETTE["malware"], label="Malware",
            edgecolor="white")
    ax.set_yticks(y)
    ax.set_yticklabels(providers)
    ax.invert_yaxis()
    ax.set_xlabel("Sample count (status = active)")
    ax.set_title("Dataset Composition by Source Provider")
    ax.legend(loc="lower right", frameon=True)

    for i, (b, m, t) in enumerate(zip(benign, malware, totals)):
        ax.text(t + max(totals) * 0.01, i, f"{t}", va="center", fontsize=9,
                color="#37474F", fontweight="bold")
        if b:
            ax.text(b / 2, i, f"{b}", va="center", ha="center",
                    fontsize=8, color="white")
        if m:
            ax.text(b + m / 2, i, f"{m}", va="center", ha="center",
                    fontsize=8, color="white")

    ax.set_xlim(0, max(totals) * 1.12)

    out = OUT / "data_per_source.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# -------------------------------------------------------------- 4. AGENT TOOL USAGE

NODE_CATEGORY = {
    "DRIFT": "ml",
    "EVAL": "ml",
    "INFERENCE": "ml",
    "RETRAIN": "ml",
    "EXTRACTION": "ml",
    "VALIDATION": "ml",
    "FETCH": "collection",
    "DISCOVERY": "collection",
    "SELECT": "collection",
    "BOOTSTRAP": "collection",
    "SCHEDULER": "infra",
    "PREFLIGHT": "infra",
    "LLM": "llm",
    "ML": "ml",
}

CATEGORY_LABEL = {
    "ml": "ML pipeline",
    "collection": "Sample collection",
    "intel": "Threat intel",
    "infra": "Infrastructure",
    "llm": "LLM reasoning",
}


def fig_agent_tool_usage() -> Path:
    if not AGENT_LOG.exists():
        raise RuntimeError(f"missing {AGENT_LOG}")
    text = AGENT_LOG.read_text(encoding="utf-8", errors="ignore")
    counts = Counter(re.findall(r"\[([A-Z_]+)\]", text))

    # keep only known categories
    items = [(tag, n) for tag, n in counts.items() if tag in NODE_CATEGORY]
    items.sort(key=lambda x: x[1], reverse=True)
    tags = [t for t, _ in items]
    vals = [v for _, v in items]
    colors = [PALETTE[NODE_CATEGORY[t]] for t in tags]

    fig, ax = plt.subplots(figsize=(10, 6))
    y = list(range(len(tags)))
    bars = ax.barh(y, vals, color=colors, edgecolor="white", linewidth=0.6)
    ax.set_yticks(y)
    ax.set_yticklabels(tags)
    ax.invert_yaxis()
    ax.set_xlabel("Invocations (log-tag occurrences)")
    ax.set_title("Agent Tool / Node Activation Counts")

    for bar, v in zip(bars, vals):
        ax.text(v + max(vals) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{v}", va="center", fontsize=9, fontweight="bold",
                color="#263238")

    handles = [Patch(facecolor=PALETTE[c], label=label)
               for c, label in CATEGORY_LABEL.items()
               if any(NODE_CATEGORY[t] == c for t in tags)]
    ax.legend(handles=handles, loc="lower right", frameon=True, title="Category")
    ax.set_xlim(0, max(vals) * 1.12)

    out = OUT / "agent_tool_usage.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ============================================================== NEW PAPER FIGS
# Figures 5–9 below are added for the academic paper.
# They complement the original 4 figures without modifying them.
# ==============================================================================


# ------------------------------------------------ 5. LANGGRAPH SYSTEM ARCHITECTURE

# Node layout coordinates (hand-tuned for clean academic look)
_ARCH_NODES = [
    # (id, label, x, y, style)
    ("start",       "START",                0.50, 0.98, "start"),
    ("selector",    "Source\nSelector",      0.50, 0.88, "collection"),
    ("pe_disc",     "PE Source\nDiscovery",  0.22, 0.78, "collection"),
    ("src_disc",    "Source\nDiscovery",     0.50, 0.73, "collection"),
    ("fetch",       "Binary\nFetch",        0.50, 0.63, "collection"),
    ("validate",    "Data\nValidation",     0.50, 0.53, "infra"),
    ("extract",     "Feature\nExtraction",  0.50, 0.43, "ml"),
    ("drift",       "Drift\nMonitor",       0.50, 0.33, "ml"),
    ("inference",   "Classifier\nInference",0.18, 0.20, "ml"),
    ("explain",     "Explain Drift\nContext",0.50, 0.20, "llm"),
    ("retrain",     "Model\nRetrain",       0.68, 0.20, "ml"),
    ("evaluation",  "Evaluation\n(TESSERACT)", 0.50, 0.08, "ml"),
    ("end",         "END",                  0.50, 0.00, "start"),
]

# Edges: (from, to, style, label)
_ARCH_EDGES = [
    ("start",     "selector",   "solid",  ""),
    ("selector",  "pe_disc",    "dashed", "low PE\ncatalog"),
    ("selector",  "src_disc",   "solid",  ""),
    ("pe_disc",   "src_disc",   "solid",  ""),
    ("src_disc",  "fetch",      "solid",  ""),
    ("fetch",     "validate",   "solid",  ""),
    ("validate",  "extract",    "solid",  ""),
    ("extract",   "drift",      "solid",  ""),
    ("drift",     "inference",  "solid",  "no drift"),
    ("drift",     "explain",    "solid",  "drift\ndetected"),
    ("drift",     "retrain",    "dashed", "threshold\nretrain"),
    ("explain",   "retrain",    "solid",  ""),
    ("inference", "evaluation", "solid",  ""),
    ("retrain",   "evaluation", "solid",  ""),
    ("evaluation","end",        "solid",  ""),
]

# Style palette for architecture nodes
_ARCH_STYLE = {
    "collection": {"fc": "#E8F5E9", "ec": "#2E7D32", "tc": "#1B5E20"},
    "ml":         {"fc": "#E3F2FD", "ec": "#1565C0", "tc": "#0D47A1"},
    "llm":        {"fc": "#F3E5F5", "ec": "#7B1FA2", "tc": "#4A148C"},
    "infra":      {"fc": "#ECEFF1", "ec": "#546E7A", "tc": "#263238"},
    "start":      {"fc": "#37474F", "ec": "#263238", "tc": "#FFFFFF"},
}


def fig_langgraph_architecture() -> Path:
    """Figure 5: LangGraph system architecture block diagram."""
    from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

    fig, ax = plt.subplots(figsize=(10, 13))
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.set_aspect("equal")
    ax.axis("off")
    ax.set_title(
        "LangGraph Pipeline Architecture",
        fontsize=15, fontweight="bold", pad=18,
    )

    node_pos: dict[str, tuple[float, float]] = {}
    BOX_W, BOX_H = 0.17, 0.065
    START_R = 0.025

    for nid, label, x, y, style in _ARCH_NODES:
        node_pos[nid] = (x, y)
        s = _ARCH_STYLE[style]

        if style == "start":
            circ = plt.Circle((x, y), START_R, fc=s["fc"], ec=s["ec"],
                              linewidth=2, zorder=3)
            ax.add_patch(circ)
            ax.text(x, y, label, ha="center", va="center",
                    fontsize=8, fontweight="bold", color=s["tc"], zorder=4)
        else:
            box = FancyBboxPatch(
                (x - BOX_W / 2, y - BOX_H / 2), BOX_W, BOX_H,
                boxstyle="round,pad=0.012", fc=s["fc"], ec=s["ec"],
                linewidth=1.8, zorder=3,
            )
            ax.add_patch(box)
            ax.text(x, y, label, ha="center", va="center",
                    fontsize=8, fontweight="bold", color=s["tc"],
                    linespacing=1.1, zorder=4)

    for src, dst, ls, label in _ARCH_EDGES:
        x0, y0 = node_pos[src]
        x1, y1 = node_pos[dst]
        linestyle = "--" if ls == "dashed" else "-"
        color = "#546E7A" if ls == "solid" else "#90A4AE"

        # Offset start/end to avoid drawing inside boxes
        dy = y1 - y0
        dx = x1 - x0
        mag = max((dx**2 + dy**2) ** 0.5, 1e-9)
        offset_start = START_R + 0.005 if _ARCH_STYLE.get(
            next((s for n, _, _, _, s in _ARCH_NODES if n == src), ""), {}
        ) == "start" else BOX_H / 2 + 0.005
        offset_end = START_R + 0.005 if _ARCH_STYLE.get(
            next((s for n, _, _, _, s in _ARCH_NODES if n == dst), ""), {}
        ) == "start" else BOX_H / 2 + 0.005

        # Adjust for the start/end node lookup
        src_style = next((s for n, _, _, _, s in _ARCH_NODES if n == src), "")
        dst_style = next((s for n, _, _, _, s in _ARCH_NODES if n == dst), "")
        offset_s = (START_R + 0.005) if src_style == "start" else (BOX_H / 2 + 0.005)
        offset_e = (START_R + 0.005) if dst_style == "start" else (BOX_H / 2 + 0.005)

        ax.annotate(
            "", xy=(x1, y1 + offset_e * (1 if dy < 0 else -1) if abs(dy) > abs(dx) else y1),
            xytext=(x0, y0 - offset_s * (1 if dy < 0 else -1) if abs(dy) > abs(dx) else y0),
            arrowprops=dict(
                arrowstyle="-|>", color=color, linewidth=1.5,
                linestyle=linestyle, shrinkA=4, shrinkB=4,
            ),
            zorder=2,
        )

        if label:
            mx = (x0 + x1) / 2
            my = (y0 + y1) / 2
            # Offset label to avoid arrow overlap
            lx_off = 0.06 if abs(dx) > 0.15 else 0.09 * (-1 if x0 > x1 else 1)
            ax.text(mx + lx_off, my, label, fontsize=6.5, color="#455A64",
                    ha="center", va="center", style="italic",
                    bbox=dict(boxstyle="round,pad=0.15", fc="white",
                              ec="none", alpha=0.85),
                    zorder=5)

    # Legend for node categories
    from matplotlib.patches import Patch as LegendPatch
    legend_items = [
        LegendPatch(facecolor="#E8F5E9", edgecolor="#2E7D32", label="Sample Collection"),
        LegendPatch(facecolor="#E3F2FD", edgecolor="#1565C0", label="ML Pipeline"),
        LegendPatch(facecolor="#F3E5F5", edgecolor="#7B1FA2", label="LLM Reasoning"),
        LegendPatch(facecolor="#ECEFF1", edgecolor="#546E7A", label="Validation"),
    ]
    ax.legend(handles=legend_items, loc="lower left", fontsize=8,
              frameon=True, framealpha=0.9, title="Node Category",
              title_fontsize=9)

    out = OUT / "langgraph_architecture.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# -------------------------------------------- 6. TEMPORAL PERFORMANCE DECAY (LINE)

def fig_temporal_performance_decay() -> Path:
    """Figure 6: TESSERACT temporal accuracy/FPR across evaluation runs.

    Uses model_update_log entries with status=ok as the primary data,
    then overlays retrograde accuracy from evaluation_log if available.
    """
    import numpy as np

    # ---- primary: model_update_log (every retrain event with holdout)
    rows = _read_jsonl(MODEL_LOG)
    points = [r for r in rows if r.get("status") == "ok" and r.get("updated_metrics")]
    points.sort(key=lambda r: r["timestamp"])

    if not points:
        raise RuntimeError("no model_update_log rows with status=ok")

    run_idx = list(range(1, len(points) + 1))
    accs = [float(r["updated_metrics"].get("accuracy", 0)) for r in points]
    fprs = [float(r["updated_metrics"].get("fpr", 0)) for r in points]
    triggers = [r.get("trigger", "") for r in points]

    # ---- secondary: evaluation_log retrograde accuracy (if any)
    eval_rows = _read_jsonl(EVAL_LOG)
    eval_rows.sort(key=lambda r: r.get("timestamp", ""))
    retro_vals = []
    retro_idx = []
    for i, er in enumerate(eval_rows):
        m = er.get("metrics", {})
        ra = m.get("retrograde_accuracy")
        if ra is not None:
            retro_vals.append(float(ra))
            retro_idx.append(i + 1)

    # ---- smoothed accuracy trendline (rolling average, window=5)
    window = min(5, len(accs))
    if window >= 2:
        smooth = np.convolve(accs, np.ones(window) / window, mode="valid")
        smooth_x = list(range(window, len(accs) + 1))
    else:
        smooth, smooth_x = None, None

    # ---- drift event indices (map timestamps to nearest run_idx)
    drift_events = _read_jsonl(DRIFT_LOG)
    drift_ts_set = {e["timestamp"][:16] for e in drift_events}

    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(12, 7), sharex=True,
        gridspec_kw={"height_ratios": [3.2, 1], "hspace": 0.08},
    )

    # ---- Top: Accuracy + TPR + trend
    ax1.plot(run_idx, accs, marker="o", markersize=4.5, linewidth=1.6,
             color=PALETTE["accuracy"], label="Holdout Accuracy", zorder=3)
    if smooth is not None:
        ax1.plot(smooth_x, smooth, linewidth=2.5, color="#0D47A1",
                 alpha=0.4, linestyle="-", label=f"Trend (MA-{window})", zorder=2)
    if retro_vals:
        ax1.plot(retro_idx, retro_vals, marker="D", markersize=5, linewidth=1.4,
                 color="#7B1FA2", linestyle="--", label="Retrograde Accuracy",
                 zorder=3, alpha=0.85)

    # Mark drift events with vertical lines
    for i, p in enumerate(points):
        if p.get("trigger") == "drift_detected":
            ax1.axvline(run_idx[i], color=PALETTE["drift"], alpha=0.15,
                        linewidth=6, zorder=1)

    ax1.set_ylim(-0.02, 1.08)
    ax1.set_ylabel("Metric Value", fontsize=11)
    ax1.set_title("Temporal Performance Decay: Accuracy & Recovery Across Evaluations",
                  fontsize=13, fontweight="bold")
    ax1.legend(loc="lower right", ncol=3, frameon=True, framealpha=0.92, fontsize=9)

    # ---- Bottom: FPR
    ax2.fill_between(run_idx, 0, fprs, color=PALETTE["fpr"], alpha=0.22, zorder=1)
    ax2.plot(run_idx, fprs, marker="s", markersize=3.5, linewidth=1.4,
             color=PALETTE["fpr"], label="FPR", zorder=3)
    ax2.set_ylabel("FPR", fontsize=11)
    ax2.set_xlabel("Evaluation Run (chronological)", fontsize=11)
    ax2.set_ylim(-0.01, max(0.20, max(fprs) * 1.4))
    ax2.legend(loc="upper right", frameon=True, framealpha=0.9, fontsize=9)

    # X-axis ticks
    tick_step = max(1, len(run_idx) // 15)
    ax2.set_xticks(run_idx[::tick_step])

    out = OUT / "temporal_performance_decay.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ----------------------------------------- 7. DRIFT & RETRAINING IMPACT (TIMELINE)

def fig_drift_retrain_impact() -> Path:
    """Figure 7: Drift detection moments + accuracy recovery after MADAR retrain.

    Each retrain event shows pre-retrain accuracy (light bar) and
    post-retrain accuracy (solid bar), with a delta annotation.
    Only drift_detected events are shown (not threshold_retrain).
    """
    import numpy as np

    rows = _read_jsonl(MODEL_LOG)
    events = []
    for r in rows:
        if r.get("status") != "ok":
            continue
        if r.get("trigger") != "drift_detected":
            continue
        prev = r.get("previous_metrics") or {}
        post = r.get("updated_metrics") or {}
        if not prev or not post:
            continue
        events.append({
            "ts": r["timestamp"][:16],
            "pre_acc": float(prev.get("accuracy", 0)),
            "post_acc": float(post.get("accuracy", 0)),
            "pre_fpr": float(prev.get("fpr", 0)),
            "post_fpr": float(post.get("fpr", 0)),
        })

    if not events:
        raise RuntimeError("no drift_detected events with pre/post metrics")

    n = len(events)
    x = np.arange(n)
    pre = [e["pre_acc"] for e in events]
    post = [e["post_acc"] for e in events]
    deltas = [e["post_acc"] - e["pre_acc"] for e in events]
    labels = [e["ts"].split("T")[1] for e in events]  # HH:MM only

    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(14, 7.5),
        gridspec_kw={"height_ratios": [2.5, 1], "hspace": 0.15},
    )

    # ---- Top: pre/post accuracy grouped bars
    w = 0.35
    bars_pre = ax1.bar(x - w / 2, pre, w, color="#BBDEFB", edgecolor="#1565C0",
                       linewidth=0.8, label="Pre-Retrain Accuracy", zorder=2)
    bars_post = ax1.bar(x + w / 2, post, w, color="#1565C0", edgecolor="#0D47A1",
                        linewidth=0.8, label="Post-Retrain Accuracy", zorder=2)

    # Annotate improvement arrows
    for i in range(n):
        d = deltas[i]
        color = "#2E7D32" if d >= 0 else "#C62828"
        symbol = "▲" if d >= 0 else "▼"
        txt = f"{symbol}{abs(d)*100:.1f}pp"
        ypos = max(pre[i], post[i]) + 0.03
        ax1.text(x[i], min(ypos, 1.05), txt, ha="center", va="bottom",
                 fontsize=6.5, fontweight="bold", color=color, zorder=5)

    ax1.set_ylim(0, 1.15)
    ax1.set_ylabel("Holdout Accuracy", fontsize=11)
    ax1.set_title("Drift Detection & MADAR Retrain Impact on Model Accuracy",
                  fontsize=13, fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=7, rotation=45, ha="right")
    ax1.legend(loc="lower right", frameon=True, framealpha=0.92, fontsize=9)

    # Shade background alternating for readability
    for i in range(0, n, 2):
        ax1.axvspan(i - 0.5, i + 0.5, color="#F5F5F5", zorder=0)

    # ---- Bottom: accuracy delta as colored bar chart
    delta_pp = [d * 100 for d in deltas]
    bar_colors = ["#2E7D32" if d >= 0 else "#C62828" for d in deltas]
    ax2.bar(x, delta_pp, color=bar_colors, edgecolor="white", linewidth=0.5,
            width=0.6, zorder=2)
    # Value labels on delta bars
    for i, dp in enumerate(delta_pp):
        va = "bottom" if dp >= 0 else "top"
        offset = 1.0 if dp >= 0 else -1.0
        ax2.text(i, dp + offset, f"{dp:+.1f}", ha="center", va=va,
                 fontsize=6, fontweight="bold", color=bar_colors[i], zorder=4)

    ax2.axhline(0, color="#263238", linewidth=1, linestyle="-", zorder=1)
    ax2.set_ylabel("Accuracy Δ (pp)", fontsize=11)
    ax2.set_xlabel("Drift Event (by time)", fontsize=11)
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontsize=7, rotation=45, ha="right")

    # Mean delta annotation
    mean_d = sum(deltas) / len(deltas) * 100
    ax2.axhline(mean_d, color="#FF8F00", linewidth=1.3, linestyle="--", alpha=0.7)
    ax2.text(n - 1, mean_d + 1.5, f"mean = {mean_d:+.1f} pp",
             fontsize=8, color="#FF8F00", ha="right", fontweight="bold")

    out = OUT / "drift_retrain_impact.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ----------------------------------------- 8. DATA PROVENANCE EVOLUTION (STACKED)

def fig_data_provenance_evolution() -> Path:
    """Figure 8: Stacked bar — cumulative sample collection per task session.

    Each bar is one retrain/drift task; stacked segments show source providers.
    This proves autonomous collection diversity over time.
    """
    import numpy as np

    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT task_id, "
            "  COALESCE(NULLIF(source_provider, ''), 'unknown') AS provider, "
            "  COUNT(*) AS n "
            "FROM samples "
            "WHERE status = 'active' AND task_id IS NOT NULL "
            "GROUP BY task_id, provider "
            "ORDER BY task_id, n DESC"
        ).fetchall()

        task_meta = conn.execute(
            "SELECT task_id, trigger FROM task_log ORDER BY task_id"
        ).fetchall()

    if not rows:
        raise RuntimeError("no samples with task_id for provenance evolution")

    # Collect all providers and task_ids
    task_ids = sorted({r[0] for r in rows})
    providers_set: set[str] = set()
    for r in rows:
        providers_set.add(r[1])

    # Order providers by total contribution
    prov_totals: dict[str, int] = defaultdict(int)
    for r in rows:
        prov_totals[r[1]] += r[2]
    providers = sorted(prov_totals.keys(), key=lambda p: -prov_totals[p])

    # Build counts matrix
    counts: dict[str, list[int]] = {p: [] for p in providers}
    for tid in task_ids:
        task_rows = {r[1]: r[2] for r in rows if r[0] == tid}
        for p in providers:
            counts[p].append(task_rows.get(p, 0))

    # Task trigger lookup
    trigger_map = {t[0]: t[1] for t in task_meta}

    # Provider colors — distinct, muted palette for stacking
    PROV_COLORS = {
        "malwarebazaar": "#C62828",   # deep red
        "benign_net":    "#1565C0",   # deep blue
        "sysinternals":  "#2E7D32",   # deep green
        "threatfox":     "#E65100",   # deep orange
        "github":        "#6A1B9A",   # deep purple
        "otx_pulse_cti": "#00838F",   # teal
        "malshare":      "#AD1457",   # pink
        "unknown":       "#757575",   # grey
    }

    fig, ax = plt.subplots(figsize=(14, 6))
    x = np.arange(len(task_ids))
    bottom = np.zeros(len(task_ids))

    for p in providers:
        vals = np.array(counts[p], dtype=float)
        color = PROV_COLORS.get(p, "#9E9E9E")
        ax.bar(x, vals, bottom=bottom, label=p, color=color,
               edgecolor="white", linewidth=0.5, zorder=2)
        bottom += vals

    # Label bars with totals
    totals = bottom
    for i, t in enumerate(totals):
        if t > 0:
            ax.text(i, t + max(totals) * 0.012, f"{int(t)}", ha="center",
                    fontsize=7, fontweight="bold", color="#37474F", zorder=5)

    # X-axis: task_ids with trigger indicators
    xlabels = []
    for tid in task_ids:
        trig = trigger_map.get(tid, "")
        marker = "D" if trig == "drift_detected" else "T" if trig == "threshold_retrain" else "C"
        xlabels.append(f"T{tid}\n({marker})")

    ax.set_xticks(x)
    ax.set_xticklabels(xlabels, fontsize=7, rotation=0)
    ax.set_xlabel("Task Session (D = drift, T = threshold, C = cold start)", fontsize=10)
    ax.set_ylabel("Samples Collected", fontsize=11)
    ax.set_title("Data Provenance Evolution: Source Composition per Collection Session",
                 fontsize=13, fontweight="bold")
    ax.legend(loc="upper right", fontsize=8, ncol=2, frameon=True,
              framealpha=0.92, title="Source Provider", title_fontsize=9)
    ax.set_xlim(-0.7, len(task_ids) - 0.3)
    ax.set_ylim(0, max(totals) * 1.12)

    # Cumulative line
    ax_twin = ax.twinx()
    cumulative = np.cumsum(totals)
    ax_twin.plot(x, cumulative, color="#37474F", linewidth=2, linestyle="--",
                 marker="D", markersize=3.5, alpha=0.6, label="Cumulative Total")
    ax_twin.set_ylabel("Cumulative Samples", fontsize=10, color="#37474F")
    ax_twin.tick_params(axis="y", labelcolor="#546E7A")
    ax_twin.legend(loc="upper left", fontsize=8, frameon=True, framealpha=0.9)

    out = OUT / "data_provenance_evolution.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ------------------------------------------- 9. AGENT TOOL UTILIZATION (BAR GRAPH)

def fig_agent_tool_utilization() -> Path:
    """Figure 9: Agent tool/node invocation counts, grouped by functional category.

    Reads agent log tags and groups them into meaningful categories
    for the paper's Section III.B (Reusable Agent Tools).
    """
    import numpy as np

    if not AGENT_LOG.exists():
        raise RuntimeError(f"missing {AGENT_LOG}")
    text = AGENT_LOG.read_text(encoding="utf-8", errors="ignore")
    raw_counts = Counter(re.findall(r"\[([A-Z_]+)\]", text))

    # Curated grouping with readable labels
    TOOL_GROUPS = {
        "Drift Detection":     {"tags": ["DRIFT"],          "color": "#C62828"},
        "LLM Reasoning":       {"tags": ["LLM"],            "color": "#7B1FA2"},
        "Source Discovery":    {"tags": ["DISCOVERY"],       "color": "#2E7D32"},
        "Scheduler Control":   {"tags": ["SCHEDULER"],       "color": "#546E7A"},
        "TESSERACT Eval":      {"tags": ["EVAL"],            "color": "#0277BD"},
        "Binary Fetch":        {"tags": ["FETCH"],           "color": "#E65100"},
        "Data Validation":     {"tags": ["VALIDATION"],      "color": "#00695C"},
        "Feature Extraction":  {"tags": ["EXTRACTION"],      "color": "#1565C0"},
        "Model Retrain":       {"tags": ["RETRAIN"],         "color": "#AD1457"},
        "Source Selection":    {"tags": ["SELECT"],           "color": "#33691E"},
        "Preflight Check":    {"tags": ["PREFLIGHT"],        "color": "#37474F"},
        "ML Inference":        {"tags": ["INFERENCE"],        "color": "#4527A0"},
        "Bootstrap":           {"tags": ["BOOTSTRAP"],        "color": "#BF360C"},
    }

    items = []
    for label, cfg_item in TOOL_GROUPS.items():
        count = sum(raw_counts.get(t, 0) for t in cfg_item["tags"])
        if count > 0:
            items.append((label, count, cfg_item["color"]))

    items.sort(key=lambda x: x[1], reverse=True)

    if not items:
        raise RuntimeError("no tool invocations found in agent log")

    labels = [it[0] for it in items]
    vals = [it[1] for it in items]
    colors = [it[2] for it in items]

    fig, ax = plt.subplots(figsize=(11, 7))
    y = np.arange(len(labels))
    bars = ax.barh(y, vals, color=colors, edgecolor="white", linewidth=0.7,
                   height=0.7, zorder=2)

    # Value labels
    max_val = max(vals)
    for bar, v in zip(bars, vals):
        ax.text(v + max_val * 0.015, bar.get_y() + bar.get_height() / 2,
                f"{v}", va="center", fontsize=9.5, fontweight="bold",
                color="#263238", zorder=4)

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("Invocation Count (log-tag occurrences)", fontsize=11)
    ax.set_title("Agent Tool & Node Utilization Breakdown",
                 fontsize=13, fontweight="bold")
    ax.set_xlim(0, max_val * 1.15)

    # Category grouping legend (functional areas)
    from matplotlib.patches import Patch as LPatch
    cat_legend = {
        "ML Pipeline":      ["#C62828", "#1565C0", "#0277BD", "#AD1457", "#4527A0"],
        "Data Collection":  ["#2E7D32", "#E65100", "#00695C", "#33691E", "#BF360C"],
        "Intelligence":     ["#7B1FA2"],
        "Infrastructure":   ["#546E7A", "#37474F"],
    }
    handles = []
    for cat, cat_colors in cat_legend.items():
        handles.append(LPatch(facecolor=cat_colors[0], edgecolor="white",
                              label=cat))
    ax.legend(handles=handles, loc="lower right", frameon=True,
              framealpha=0.92, title="Functional Area", title_fontsize=9,
              fontsize=8)

    # Percentage annotations on bars
    total = sum(vals)
    for bar, v in zip(bars, vals):
        pct = v / total * 100
        if pct >= 3.0:
            ax.text(v - max_val * 0.01, bar.get_y() + bar.get_height() / 2,
                    f"{pct:.1f}%", va="center", ha="right", fontsize=7.5,
                    color="white", fontweight="bold", zorder=5)

    out = OUT / "agent_tool_utilization.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# -------------------------------------------------------------- main

def main() -> None:
    figs = [
        ("performance_over_time",       fig_perf_over_time),
        ("drift_per_session",           fig_drift_per_session),
        ("data_per_source",             fig_data_per_source),
        ("agent_tool_usage",            fig_agent_tool_usage),
        # New academic paper figures
        ("langgraph_architecture",      fig_langgraph_architecture),
        ("temporal_performance_decay",  fig_temporal_performance_decay),
        ("drift_retrain_impact",        fig_drift_retrain_impact),
        ("data_provenance_evolution",   fig_data_provenance_evolution),
        ("agent_tool_utilization",      fig_agent_tool_utilization),
    ]
    for name, fn in figs:
        try:
            path = fn()
            print(f"[ok]   {name:35s} -> {path.relative_to(ROOT)}")
        except Exception as exc:
            print(f"[FAIL] {name:35s} : {exc}")


if __name__ == "__main__":
    main()

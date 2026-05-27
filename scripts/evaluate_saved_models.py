#!/usr/bin/env python3
"""
Evaluate all saved model bundles in data/models/*.pkl against SQLite labeled samples.

Outputs:
- report/model_eval/model_eval.json  (canonical; used by plot script)
- report/model_eval/model_eval.csv   (metrics table)
- report/model_eval/confusion_matrices.csv
- report/model_eval/REPORT.md        (human-friendly ranking)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def _load_project_env() -> None:
    """Load .env into os.environ (setdefault) so scripts work outside Docker."""
    import os

    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_project_env()

try:
    import joblib  # type: ignore
except Exception:  # pragma: no cover
    joblib = None


@dataclass(frozen=True)
class Confusion:
    tn: int
    fp: int
    fn: int
    tp: int


@dataclass(frozen=True)
class Metrics:
    accuracy: float
    precision: float
    recall: float
    tpr: float
    fpr: float


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_float(x: Any) -> float | None:
    try:
        if x is None:
            return None
        v = float(x)
        if not np.isfinite(v):
            return None
        return v
    except Exception:
        return None


def _confusion(y_true: np.ndarray, y_pred: np.ndarray) -> Confusion:
    y_true = y_true.astype(int)
    y_pred = y_pred.astype(int)
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    return Confusion(tn=tn, fp=fp, fn=fn, tp=tp)


def _binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, conf: Confusion) -> Metrics:
    n = max(int(len(y_true)), 1)
    acc = (conf.tp + conf.tn) / n
    precision = conf.tp / (conf.tp + conf.fp) if (conf.tp + conf.fp) else 0.0
    recall = conf.tp / (conf.tp + conf.fn) if (conf.tp + conf.fn) else 0.0
    fpr = conf.fp / (conf.fp + conf.tn) if (conf.fp + conf.tn) else 0.0
    return Metrics(
        accuracy=float(acc),
        precision=float(precision),
        recall=float(recall),
        tpr=float(recall),
        fpr=float(fpr),
    )


def _is_bundle(obj: Any) -> bool:
    return isinstance(obj, dict) and "model" in obj


def _load_bundle(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        if joblib is not None:
            raw = joblib.load(path)
        else:
            import pickle

            with path.open("rb") as f:
                raw = pickle.load(f)
    except Exception as exc:
        loader = "joblib.load" if joblib is not None else "pickle.load"
        return None, f"{loader} failed: {exc}"
    if not _is_bundle(raw):
        return None, "not a bundle dict (expected keys like 'model', 'threshold', ...)"
    return raw, None


def _bundle_threshold(bundle: dict[str, Any]) -> tuple[float, str | None]:
    thr = _safe_float(bundle.get("threshold"))
    if thr is None:
        return 0.5, "missing/invalid threshold; defaulted to 0.5"
    return float(min(max(thr, 0.0), 1.0)), None


def _maybe_auc(y_true: np.ndarray, scores: np.ndarray) -> float | None:
    if len(y_true) == 0 or len(np.unique(y_true)) < 2:
        return None
    try:
        # AUC via rank statistic (equivalent to Mann–Whitney U):
        # AUC = (sum(ranks_pos) - n_pos*(n_pos+1)/2) / (n_pos*n_neg)
        y = y_true.astype(int)
        s = np.asarray(scores, dtype=np.float64)
        pos = s[y == 1]
        neg = s[y == 0]
        n_pos = int(len(pos))
        n_neg = int(len(neg))
        if n_pos == 0 or n_neg == 0:
            return None

        # Average ranks for ties.
        order = np.argsort(s, kind="mergesort")
        sorted_scores = s[order]
        ranks = np.empty_like(sorted_scores, dtype=np.float64)
        i = 0
        cur_rank = 1.0
        while i < len(sorted_scores):
            j = i + 1
            while j < len(sorted_scores) and sorted_scores[j] == sorted_scores[i]:
                j += 1
            avg_rank = (cur_rank + (cur_rank + (j - i) - 1.0)) / 2.0
            ranks[i:j] = avg_rank
            cur_rank += float(j - i)
            i = j
        inv = np.empty_like(order)
        inv[order] = np.arange(len(order))
        full_ranks = ranks[inv]
        sum_ranks_pos = float(np.sum(full_ranks[y == 1]))
        auc = (sum_ranks_pos - (n_pos * (n_pos + 1)) / 2.0) / float(n_pos * n_neg)
        if not np.isfinite(auc):
            return None
        return float(min(max(auc, 0.0), 1.0))
    except Exception:
        return None


def _maybe_roc(y_true: np.ndarray, scores: np.ndarray) -> dict[str, list[float]] | None:
    if len(y_true) == 0 or len(np.unique(y_true)) < 2:
        return None
    try:
        y = y_true.astype(int)
        s = np.asarray(scores, dtype=np.float64)
        # Sort by score descending
        order = np.argsort(-s, kind="mergesort")
        y_sorted = y[order]
        s_sorted = s[order]
        n_pos = int(np.sum(y == 1))
        n_neg = int(np.sum(y == 0))
        if n_pos == 0 or n_neg == 0:
            return None

        tps = 0
        fps = 0
        fpr: list[float] = [0.0]
        tpr: list[float] = [0.0]
        thresholds: list[float] = [float("inf")]

        i = 0
        while i < len(s_sorted):
            thr = s_sorted[i]
            j = i
            # process all tied scores together
            while j < len(s_sorted) and s_sorted[j] == thr:
                if y_sorted[j] == 1:
                    tps += 1
                else:
                    fps += 1
                j += 1
            fpr.append(float(fps) / float(n_neg))
            tpr.append(float(tps) / float(n_pos))
            thresholds.append(float(thr))
            i = j

        # Ensure curve ends at (1,1)
        if fpr[-1] != 1.0 or tpr[-1] != 1.0:
            fpr.append(1.0)
            tpr.append(1.0)
            thresholds.append(float("-inf"))
        return {
            "fpr": [float(x) for x in fpr],
            "tpr": [float(x) for x in tpr],
            "thresholds": [float(x) for x in thresholds],
        }
    except Exception:
        return None


def _short_name(path: Path) -> str:
    return path.stem


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def _rank_models(models: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(m: dict[str, Any]) -> tuple[int, float, float]:
        skipped = 1 if m.get("skipped") else 0
        auc = m.get("auc")
        acc = (m.get("metrics") or {}).get("accuracy")
        auc_v = float(auc) if isinstance(auc, (int, float)) else -1.0
        acc_v = float(acc) if isinstance(acc, (int, float)) else -1.0
        return (skipped, -auc_v, -acc_v)

    return sorted(models, key=key)


def _write_markdown_report(path: Path, payload: dict[str, Any]) -> None:
    ds = payload.get("dataset", {})
    models = payload.get("models", [])
    ranked = _rank_models(models)
    lines: list[str] = []
    lines.append("# Model Evaluation Report")
    lines.append("")
    lines.append(f"- Generated: `{payload.get('generated_at', '')}`")
    lines.append(f"- DB: `{ds.get('db_path', '')}`")
    lines.append(
        f"- Dataset: n={ds.get('n_total', 0)} malware={ds.get('n_malware', 0)} benign={ds.get('n_benign', 0)}"
    )
    lines.append("")
    if not models:
        lines.append("No models found.")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return

    lines.append("## Ranking (best first)")
    lines.append("")
    for i, m in enumerate(ranked, start=1):
        name = m.get("name", "")
        auc = m.get("auc")
        metrics = m.get("metrics") or {}
        skipped = m.get("skipped", False)
        note = ""
        if skipped:
            note = f" (skipped: {m.get('skip_reason', '')})"
        lines.append(
            f"{i}. **{name}** — AUC={auc if auc is not None else 'n/a'} "
            f"Acc={metrics.get('accuracy', 'n/a')} FPR={metrics.get('fpr', 'n/a')}{note}"
        )
    lines.append("")
    lines.append("## Per-model details")
    lines.append("")
    for m in ranked:
        lines.append(f"### {m.get('name', '')}")
        lines.append(f"- Path: `{m.get('path', '')}`")
        if m.get("skipped"):
            lines.append(f"- Skipped: `{m.get('skip_reason', '')}`")
            lines.append("")
            continue
        lines.append(f"- Threshold: `{m.get('threshold', '')}`")
        lines.append(f"- AUC: `{m.get('auc', '')}`")
        conf = m.get("confusion") or {}
        metrics = m.get("metrics") or {}
        lines.append(
            f"- Confusion (tn/fp/fn/tp): `{conf.get('tn')}/{conf.get('fp')}/{conf.get('fn')}/{conf.get('tp')}`"
        )
        lines.append(
            f"- Metrics: Acc=`{metrics.get('accuracy')}` Prec=`{metrics.get('precision')}` "
            f"TPR=`{metrics.get('tpr')}` FPR=`{metrics.get('fpr')}`"
        )
        notes = m.get("notes") or []
        if notes:
            lines.append("- Notes:")
            for n in notes:
                lines.append(f"  - `{n}`")
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def evaluate_models(
    model_paths: list[Path],
    *,
    db_path: Path | None,
    out_dir: Path,
    include_roc_points: bool,
) -> dict[str, Any]:
    try:
        import src.config as cfg  # type: ignore
        import src.db.tracker as db  # type: ignore
        from src.ml.classifier import build_training_arrays, score_feature_matrix  # type: ignore
    except ModuleNotFoundError as exc:
        missing = getattr(exc, "name", None) or str(exc)
        raise RuntimeError(
            "Missing required dependencies for evaluation.\n"
            f"- Missing module: {missing}\n"
            "- Fix: install project requirements, e.g. `python -m pip install -r requirements.txt`\n"
        ) from exc

    cfg.ensure_dirs()
    tracker = db.get_tracker(db_path)
    X, y, hashes = build_training_arrays(tracker)

    dataset = {
        "db_path": str(tracker.db_path),
        "n_total": int(len(y)),
        "n_malware": int(np.sum(y == 1)) if len(y) else 0,
        "n_benign": int(np.sum(y == 0)) if len(y) else 0,
        "feature_set_version": str(cfg.FEATURE_SET_VERSION),
        "feature_dim": int(cfg.FEATURE_DIM),
    }

    models: list[dict[str, Any]] = []
    for path in model_paths:
        bundle, load_err = _load_bundle(path)
        entry: dict[str, Any] = {
            "path": str(path),
            "name": _short_name(path),
            "skipped": False,
            "skip_reason": "",
            "threshold": None,
            "auc": None,
            "metrics": None,
            "confusion": None,
            "roc": None,
            "notes": [],
        }
        if load_err or bundle is None:
            entry["skipped"] = True
            entry["skip_reason"] = load_err or "unknown load error"
            models.append(entry)
            continue

        threshold, thr_note = _bundle_threshold(bundle)
        entry["threshold"] = threshold
        if thr_note:
            entry["notes"].append(thr_note)

        b_ver = bundle.get("feature_set_version")
        b_dim = bundle.get("feature_dim")
        if b_ver != cfg.FEATURE_SET_VERSION or int(b_dim or 0) != int(cfg.FEATURE_DIM):
            entry["notes"].append(
                f"bundle feature metadata mismatch: version={b_ver} dim={b_dim} "
                f"(expected {cfg.FEATURE_SET_VERSION}/{cfg.FEATURE_DIM})"
            )

        if len(y) == 0:
            entry["skipped"] = True
            entry["skip_reason"] = "no labeled samples with features in SQLite"
            models.append(entry)
            continue

        try:
            scores = score_feature_matrix(bundle, X)
        except Exception as exc:
            entry["skipped"] = True
            entry["skip_reason"] = f"scoring failed: {exc}"
            models.append(entry)
            continue

        y_pred = (scores >= threshold).astype(int)
        conf = _confusion(y, y_pred)
        metrics = _binary_metrics(y, y_pred, conf)
        entry["confusion"] = asdict(conf)
        entry["metrics"] = asdict(metrics)
        entry["auc"] = _maybe_auc(y, scores)
        if include_roc_points:
            entry["roc"] = _maybe_roc(y, scores)
        models.append(entry)

    payload = {
        "generated_at": _now_iso(),
        "dataset": dataset,
        "models_glob": str(model_paths[0].parent / "*.pkl") if model_paths else "",
        "models": models,
        "artifacts": {
            "json": str(out_dir / "model_eval.json"),
            "csv": str(out_dir / "model_eval.csv"),
            "confusion_csv": str(out_dir / "confusion_matrices.csv"),
            "report_md": str(out_dir / "REPORT.md"),
        },
        "hashes_in_order": hashes,
    }
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate all saved models under data/models/*.pkl.")
    parser.add_argument(
        "--models-glob",
        default=str(Path("data") / "models" / "*.pkl"),
        help="Glob for model bundles (joblib .pkl). Default: data/models/*.pkl",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Optional SQLite DB path. Default uses src.config.DB_PATH",
    )
    parser.add_argument(
        "--out-dir",
        default=str(Path("report") / "model_eval"),
        help="Output directory for report artifacts. Default: report/model_eval/",
    )
    parser.add_argument(
        "--include-roc-points",
        action="store_true",
        help="Include ROC curve points in JSON output (used for roc_curves.png).",
    )
    args = parser.parse_args()

    model_paths = sorted(Path().glob(args.models_glob))
    out_dir = Path(args.out_dir)
    db_path = Path(args.db_path) if args.db_path else None

    try:
        payload = evaluate_models(
            model_paths,
            db_path=db_path,
            out_dir=out_dir,
            include_roc_points=bool(args.include_roc_points),
        )
    except RuntimeError as exc:
        # Graceful exit for minimal environments (missing ML deps).
        print(str(exc).strip())
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "model_eval.json"
    _write_json(json_path, payload)

    # CSVs
    metric_rows: list[dict[str, Any]] = []
    cm_rows: list[dict[str, Any]] = []
    for m in payload.get("models", []):
        base = {
            "name": m.get("name", ""),
            "path": m.get("path", ""),
            "skipped": bool(m.get("skipped", False)),
            "skip_reason": m.get("skip_reason", ""),
            "threshold": m.get("threshold", ""),
            "auc": m.get("auc", ""),
        }
        metrics = m.get("metrics") or {}
        conf = m.get("confusion") or {}
        metric_rows.append(
            {
                **base,
                "accuracy": metrics.get("accuracy", ""),
                "precision": metrics.get("precision", ""),
                "tpr": metrics.get("tpr", ""),
                "recall": metrics.get("recall", ""),
                "fpr": metrics.get("fpr", ""),
            }
        )
        cm_rows.append(
            {
                **base,
                "tn": conf.get("tn", ""),
                "fp": conf.get("fp", ""),
                "fn": conf.get("fn", ""),
                "tp": conf.get("tp", ""),
            }
        )

    _write_csv(
        out_dir / "model_eval.csv",
        metric_rows,
        fieldnames=[
            "name",
            "path",
            "skipped",
            "skip_reason",
            "threshold",
            "auc",
            "accuracy",
            "precision",
            "tpr",
            "recall",
            "fpr",
        ],
    )
    _write_csv(
        out_dir / "confusion_matrices.csv",
        cm_rows,
        fieldnames=[
            "name",
            "path",
            "skipped",
            "skip_reason",
            "threshold",
            "auc",
            "tn",
            "fp",
            "fn",
            "tp",
        ],
    )
    _write_markdown_report(out_dir / "REPORT.md", payload)

    n_models = len(payload.get("models", []))
    n_skipped = sum(1 for m in payload.get("models", []) if m.get("skipped"))
    ds = payload.get("dataset", {})
    print(f"Wrote: {json_path}")
    print(f"Models: {n_models} (skipped: {n_skipped})")
    print(
        f"Dataset: n={ds.get('n_total', 0)} malware={ds.get('n_malware', 0)} benign={ds.get('n_benign', 0)}"
    )


if __name__ == "__main__":
    main()


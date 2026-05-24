"""Shared row parsing and UTC helpers for DB repositories."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    if d.get("features_json"):
        d["features"] = json.loads(d["features_json"])
    return d


def parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

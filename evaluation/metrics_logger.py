"""Append structured experiment rows (JSONL)."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict


def default_log_path() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    d = os.path.join(root, "experiments", "logs")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "triage_runs.jsonl")


def log_experiment_row(row: Dict[str, Any], path: str | None = None) -> str:
    p = path or default_log_path()
    row = {
        **row,
        "logged_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, default=str) + "\n")
    return p


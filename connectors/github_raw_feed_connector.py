from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests

from utils.schema import Event


class GitHubRawFeedConnectorError(Exception):
    pass


def _mk_event(payload: Dict[str, Any], source_name: str) -> Event:
    raw = json.dumps(payload, ensure_ascii=True)[:1200]
    ts = datetime.now(timezone.utc)
    for key in ("timestamp", "time", "date", "created_at", "updated_at"):
        if payload.get(key):
            try:
                from dateutil import parser as dt_parser

                ts = dt_parser.parse(str(payload[key]))
            except Exception:
                pass
            break
    return Event(
        timestamp=ts,
        log_source=source_name,
        event_type=str(payload.get("event_type") or payload.get("type") or "github_feed_event"),
        raw_log=raw,
        user=str(payload.get("user") or payload.get("actor") or "") or None,
        src_ip=str(payload.get("src_ip") or payload.get("ip") or "") or None,
        dst_ip=str(payload.get("dst_ip") or payload.get("destination_ip") or "") or None,
        host=str(payload.get("host") or payload.get("device") or payload.get("repo") or "") or None,
        severity=str(payload.get("severity") or "info").lower(),
        tags=["github_feed", "osint_live"],
        extra=payload,
    )


class GitHubRawFeedConnector:
    def fetch(self, raw_url: str, fmt: str = "jsonl", limit: int = 500) -> List[Event]:
        if not raw_url.strip():
            raise GitHubRawFeedConnectorError("Raw feed URL is required.")
        try:
            r = requests.get(raw_url.strip(), timeout=25)
        except requests.RequestException as exc:
            raise GitHubRawFeedConnectorError(f"Feed request failed: {exc}") from exc
        if r.status_code >= 400:
            raise GitHubRawFeedConnectorError(f"Feed HTTP {r.status_code}")
        text = r.text
        fmt = fmt.lower().strip()
        rows: List[Dict[str, Any]] = []
        if fmt == "jsonl":
            for ln in text.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    obj = json.loads(ln)
                    if isinstance(obj, dict):
                        rows.append(obj)
                except Exception:
                    continue
        elif fmt == "json":
            try:
                obj = json.loads(text)
            except Exception as exc:
                raise GitHubRawFeedConnectorError("Invalid JSON feed") from exc
            if isinstance(obj, list):
                rows = [x for x in obj if isinstance(x, dict)]
            elif isinstance(obj, dict):
                candidate = obj.get("items") or obj.get("events") or obj.get("data")
                if isinstance(candidate, list):
                    rows = [x for x in candidate if isinstance(x, dict)]
                else:
                    rows = [obj]
        elif fmt == "csv":
            rdr = csv.DictReader(io.StringIO(text))
            rows = [dict(r) for r in rdr]
        else:
            raise GitHubRawFeedConnectorError(f"Unsupported format: {fmt}")
        rows = rows[:limit]
        return [_mk_event(rw, "github_raw_feed") for rw in rows]

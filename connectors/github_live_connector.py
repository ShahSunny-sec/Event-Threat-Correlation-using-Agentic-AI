from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from dateutil import parser as dt_parser

from utils.schema import Event


class GitHubLiveConnectorError(Exception):
    pass


def _to_event(item: Dict[str, Any]) -> Event:
    actor = (item.get("actor") or {}).get("login")
    repo = (item.get("repo") or {}).get("name")
    etype = (item.get("type") or "GitHubEvent").lower()
    created_at = item.get("created_at")
    ts: Optional[datetime] = None
    if created_at:
        try:
            ts = dt_parser.parse(created_at)
        except Exception:
            ts = None
    return Event(
        timestamp=ts,
        log_source="github_live",
        event_type=f"github_{etype}",
        raw_log=str(item)[:1200],
        user=actor,
        host=repo,
        severity="info",
        tags=["github", "live_log"],
        extra={"github_type": item.get("type"), "repo": repo},
    )


class GitHubLiveConnector:
    def __init__(self, token: str = "", repo: str = "") -> None:
        self.token = token.strip()
        self.repo = repo.strip()

    def fetch_events(self, limit: int = 100) -> List[Event]:
        if self.repo:
            url = f"https://api.github.com/repos/{self.repo}/events"
        else:
            url = "https://api.github.com/events"
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            r = requests.get(url, headers=headers, timeout=20)
        except requests.RequestException as exc:
            raise GitHubLiveConnectorError(f"GitHub API request failed: {exc}") from exc
        if r.status_code >= 400:
            raise GitHubLiveConnectorError(f"GitHub API HTTP {r.status_code}: {r.text[:200]}")
        try:
            data = r.json()
        except ValueError as exc:
            raise GitHubLiveConnectorError("Invalid JSON from GitHub API") from exc
        if not isinstance(data, list):
            raise GitHubLiveConnectorError("Unexpected GitHub events payload format")
        return [_to_event(it) for it in data[:limit] if isinstance(it, dict)]

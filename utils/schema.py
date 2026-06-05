from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


def _uid() -> str:
    return uuid.uuid4().hex[:12].upper()


@dataclass
class Event:
    event_id: str = field(default_factory=lambda: f"EVT-{_uid()}")
    timestamp: Optional[datetime] = None
    log_source: str = ""
    event_type: str = ""
    raw_log: str = ""
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    host: Optional[str] = None
    alert_name: Optional[str] = None
    severity: str = "info"
    action: Optional[str] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    detection_id: str = field(default_factory=lambda: f"DET-{_uid()}")
    detection_type: str = ""
    detection_name: str = ""
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    event_ids: List[str] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    host: Optional[str] = None
    risk_score: float = 0.0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Incident:
    incident_id: str = field(default_factory=lambda: f"INC-{_uid()}")
    incident_type: str = "multi_stage_attack"
    title: str = ""
    summary: str = ""
    detections: List[DetectionResult] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    severity: str = "high"
    criticality_score: float = 0.0
    confidence: float = 0.0
    affected_user: Optional[str] = None
    affected_host: Optional[str] = None
    primary_src_ip: Optional[str] = None
    primary_dst_ip: Optional[str] = None
    correlation_keys: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    enrichment_links: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

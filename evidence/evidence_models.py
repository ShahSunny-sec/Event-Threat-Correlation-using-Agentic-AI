"""Typed artifacts for evidence-grounded incident triage."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional


DecisionLiteral = Literal["close", "escalate", "defer"]


@dataclass
class Claim:
    text: str
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"text": self.text, "evidence_ids": list(self.evidence_ids)}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Claim":
        return Claim(
            text=str(d.get("text") or ""),
            evidence_ids=[str(x) for x in (d.get("evidence_ids") or [])],
        )


@dataclass
class EvidencePack:
    incident_id: str
    incident_type: str
    candidate_decision_space: List[str]
    entities: Dict[str, Any]
    timeline: List[Dict[str, Any]]
    detections: List[Dict[str, Any]]
    enrichment: Dict[str, Any]
    mitre: Dict[str, Any]
    triage_features: Dict[str, Any]
    coverage_summary: Dict[str, Any]
    conflict_summary: Dict[str, Any]
    evidence_index: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "incident_type": self.incident_type,
            "candidate_decision_space": list(self.candidate_decision_space),
            "entities": dict(self.entities),
            "timeline": list(self.timeline),
            "detections": list(self.detections),
            "enrichment": dict(self.enrichment),
            "mitre": dict(self.mitre),
            "triage_features": dict(self.triage_features),
            "coverage_summary": dict(self.coverage_summary),
            "conflict_summary": dict(self.conflict_summary),
            "evidence_index": dict(self.evidence_index),
        }


@dataclass
class TriageOutput:
    incident_id: str
    decision: DecisionLiteral
    confidence: float
    rationale: str
    evidence_ids: List[str]
    claims: List[Claim]
    missing_information: List[str]
    uncertainty_reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "decision": self.decision,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "evidence_ids": list(self.evidence_ids),
            "claims": [c.to_dict() for c in self.claims],
            "missing_information": list(self.missing_information),
            "uncertainty_reasons": list(self.uncertainty_reasons),
        }


@dataclass
class VerifierOutput:
    incident_id: str
    is_valid: bool
    unsupported_claims: List[str]
    missing_citations: List[str]
    contradictions: List[str]
    coverage_assessment: str
    confidence_assessment: str
    recommended_final_action: DecisionLiteral

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "is_valid": self.is_valid,
            "unsupported_claims": list(self.unsupported_claims),
            "missing_citations": list(self.missing_citations),
            "contradictions": list(self.contradictions),
            "coverage_assessment": self.coverage_assessment,
            "confidence_assessment": self.confidence_assessment,
            "recommended_final_action": self.recommended_final_action,
        }


@dataclass
class FinalDecision:
    incident_id: str
    final_decision: DecisionLiteral
    reason: str
    triage_decision: Optional[DecisionLiteral]
    verifier_recommended: Optional[DecisionLiteral]
    policy_applied: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "final_decision": self.final_decision,
            "reason": self.reason,
            "triage_decision": self.triage_decision,
            "verifier_recommended": self.verifier_recommended,
            "policy_applied": self.policy_applied,
        }

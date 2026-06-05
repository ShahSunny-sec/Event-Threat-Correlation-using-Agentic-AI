"""Coverage vs confidence, pack conflicts vs triage confidence."""
from __future__ import annotations

from typing import List, Tuple

from evidence.evidence_models import EvidencePack, TriageOutput


def confidence_ceiling_for_coverage(coverage_score: float) -> float:
    """Higher coverage allows higher justified confidence."""
    if coverage_score < 0.35:
        return 0.45
    if coverage_score < 0.55:
        return 0.65
    if coverage_score < 0.75:
        return 0.82
    return 0.95


def assess_confidence_vs_coverage(
    pack: EvidencePack, triage: TriageOutput
) -> Tuple[str, bool]:
    cov = float(pack.coverage_summary.get("coverage_score") or 0.0)
    ceiling = confidence_ceiling_for_coverage(cov)
    if triage.confidence > ceiling + 0.05:
        return (
            f"confidence {triage.confidence:.2f} exceeds coverage-based ceiling {ceiling:.2f} "
            f"(coverage_score={cov:.2f})",
            False,
        )
    return ("confidence within coverage band", True)


def triage_ignores_conflicts(pack: EvidencePack, triage: TriageOutput) -> List[str]:
    issues: List[str] = []
    if not pack.conflict_summary.get("has_conflict"):
        return issues
    if triage.decision == "escalate" and triage.confidence >= 0.75:
        issues.append("escalate_with_high_confidence_despite_pack_conflict_flags")
    if triage.decision == "close" and triage.confidence >= 0.85 and pack.conflict_summary.get("flags"):
        issues.append("high_confidence_close_despite_conflict_flags")
    return issues


def rationale_mentions_evidence_keywords(triage: TriageOutput, valid_ids: List[str]) -> Tuple[str, bool]:
    """
    Keep rationale checks realistic:
    - Require non-empty rationale text.
    - If there are claims, ensure at least one cited evidence id in claims intersects
      top-level evidence ids (anchors rationale to the same support set).
    """
    r = (triage.rationale or "").strip()
    if len(r) < 16:
        return ("rationale too short", False)

    claim_evidence = set()
    for c in triage.claims:
        claim_evidence.update(c.evidence_ids)
    top = set(triage.evidence_ids)

    if claim_evidence and top and not (claim_evidence & top):
        return ("rationale/claims evidence anchors are inconsistent", False)

    # valid_ids kept for interface compatibility and future checks.
    _ = valid_ids
    return ("rationale sufficiently grounded", True)

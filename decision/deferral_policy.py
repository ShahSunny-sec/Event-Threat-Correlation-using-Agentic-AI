"""Deterministic final decision from triage + verifier + pack (close / escalate / defer)."""
from __future__ import annotations

from typing import Optional

from evidence.evidence_models import EvidencePack, FinalDecision, TriageOutput, VerifierOutput


COVERAGE_DEFER_THRESHOLD = 0.38
CONFIDENCE_MIN_NON_DEFER = 0.60
STRONG_EVIDENCE_MIN_ESCALATE = 2


def apply_deferral_policy(
    pack: EvidencePack,
    triage: Optional[TriageOutput],
    verifier: Optional[VerifierOutput],
) -> FinalDecision:
    """
    Force defer when verifier fails, coverage is thin, confidence is low,
    or insufficient strong evidence supports escalation.
    """
    iid = pack.incident_id
    cov = float(pack.coverage_summary.get("coverage_score") or 0.0)
    strong = int(pack.coverage_summary.get("strong_evidence_count") or 0)
    has_conflict = bool(pack.conflict_summary.get("has_conflict"))

    if triage is None:
        return FinalDecision(
            incident_id=iid,
            final_decision="defer",
            reason="triage_unavailable_or_failed_validation",
            triage_decision=None,
            verifier_recommended=verifier.recommended_final_action if verifier else None,
            policy_applied="no_triage",
        )

    tv = triage.decision
    tc = triage.confidence

    if verifier and not verifier.is_valid:
        return FinalDecision(
            incident_id=iid,
            final_decision="defer",
            reason="verifier_rejected_output:" + ";".join(
                verifier.unsupported_claims + verifier.missing_citations + verifier.contradictions
            )[:500],
            triage_decision=tv,
            verifier_recommended=verifier.recommended_final_action,
            policy_applied="verifier_invalid",
        )

    if cov < COVERAGE_DEFER_THRESHOLD:
        return FinalDecision(
            incident_id=iid,
            final_decision="defer",
            reason=f"coverage_score_below_{COVERAGE_DEFER_THRESHOLD}",
            triage_decision=tv,
            verifier_recommended=verifier.recommended_final_action if verifier else None,
            policy_applied="low_coverage",
        )

    if tc < CONFIDENCE_MIN_NON_DEFER and tv != "defer":
        return FinalDecision(
            incident_id=iid,
            final_decision="defer",
            reason=f"confidence_{tc:.2f}_below_{CONFIDENCE_MIN_NON_DEFER}",
            triage_decision=tv,
            verifier_recommended=verifier.recommended_final_action if verifier else None,
            policy_applied="low_confidence",
        )

    if has_conflict and tv != "defer":
        return FinalDecision(
            incident_id=iid,
            final_decision="defer",
            reason="pack_conflict_flags_require_defer_or_explicit_defer_choice",
            triage_decision=tv,
            verifier_recommended=verifier.recommended_final_action if verifier else None,
            policy_applied="conflict_guard",
        )

    if tv == "escalate" and strong < STRONG_EVIDENCE_MIN_ESCALATE:
        return FinalDecision(
            incident_id=iid,
            final_decision="defer",
            reason=f"escalate_requires_strong_evidence_count>={STRONG_EVIDENCE_MIN_ESCALATE}",
            triage_decision=tv,
            verifier_recommended=verifier.recommended_final_action if verifier else None,
            policy_applied="insufficient_strong_evidence",
        )

    if verifier and verifier.recommended_final_action == "defer" and tv != "defer":
        return FinalDecision(
            incident_id=iid,
            final_decision="defer",
            reason="verifier_recommended_defer_over_triage",
            triage_decision=tv,
            verifier_recommended=verifier.recommended_final_action,
            policy_applied="verifier_override",
        )

    return FinalDecision(
        incident_id=iid,
        final_decision=tv,
        reason="triage_accepted_under_policy",
        triage_decision=tv,
        verifier_recommended=verifier.recommended_final_action if verifier else None,
        policy_applied="accept_triage",
    )

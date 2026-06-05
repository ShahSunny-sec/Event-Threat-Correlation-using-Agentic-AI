"""Rule-based verifier for triage JSON against EvidencePack."""
from __future__ import annotations

from typing import List

from evidence.evidence_models import EvidencePack, TriageOutput, VerifierOutput
from evidence.evidence_pack_builder import all_pack_evidence_ids
from verification.consistency_checks import (
    assess_confidence_vs_coverage,
    rationale_mentions_evidence_keywords,
    triage_ignores_conflicts,
)
from verification.evidence_checks import (
    claims_missing_citations,
    top_level_evidence_ids_nonempty,
    unknown_evidence_ids,
)


def verify_triage(pack: EvidencePack, triage: TriageOutput) -> VerifierOutput:
    unsupported: List[str] = []
    missing_cit: List[str] = []
    contradictions: List[str] = []

    unk = unknown_evidence_ids(pack, triage)
    if unk:
        unsupported.append(f"unknown_evidence_ids:{unk}")

    missing_cit.extend(claims_missing_citations(triage))
    if not top_level_evidence_ids_nonempty(triage):
        missing_cit.append("top_level_evidence_ids_empty")

    msg, conf_ok = assess_confidence_vs_coverage(pack, triage)
    if not conf_ok:
        contradictions.append(msg)

    contradictions.extend(triage_ignores_conflicts(pack, triage))

    valid_ids = sorted(all_pack_evidence_ids(pack))
    _, rat_ok = rationale_mentions_evidence_keywords(triage, valid_ids)
    if not rat_ok and triage.decision != "defer":
        contradictions.append("rationale_not_evidence_anchored_for_non_defer_decision")

    is_valid = (
        len(unk) == 0
        and len(missing_cit) == 0
        and conf_ok
        and len(contradictions) == 0
    )

    cov_assess = (
        f"coverage_score={pack.coverage_summary.get('coverage_score')}, "
        f"strong_evidence={pack.coverage_summary.get('strong_evidence_count')}"
    )
    conf_assess = "ok" if conf_ok else "overconfident_for_coverage"

    if not is_valid:
        rec: str = "defer"
    elif triage.decision == "escalate" and int(pack.coverage_summary.get("strong_evidence_count") or 0) < 2:
        rec = "defer"
    elif pack.conflict_summary.get("has_conflict") and triage.decision != "defer":
        rec = "defer"
    else:
        rec = triage.decision

    return VerifierOutput(
        incident_id=pack.incident_id,
        is_valid=is_valid,
        unsupported_claims=unsupported,
        missing_citations=missing_cit,
        contradictions=contradictions,
        coverage_assessment=cov_assess,
        confidence_assessment=conf_assess,
        recommended_final_action=rec,  # type: ignore[arg-type]
    )

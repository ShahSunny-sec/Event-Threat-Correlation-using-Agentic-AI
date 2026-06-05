"""Evidence-constrained LLM triage step."""
from __future__ import annotations

from typing import List, Optional, Tuple

from agent.openai_client import chat_completion, is_llm_configured
from agent.output_parser import parse_triage_output
from agent.triage_prompts import build_triage_messages
from evidence.evidence_pack_builder import all_pack_evidence_ids
from verification.consistency_checks import confidence_ceiling_for_coverage
from evidence.evidence_models import EvidencePack, TriageOutput


def _call_triage_llm(messages: list, temperature: float, max_tokens: int) -> str:
    raw = chat_completion(
        messages,
        temperature=temperature,
        max_tokens=max_tokens,
        response_format={"type": "json_object"},
    )
    if raw:
        return raw
    return chat_completion(messages, temperature=temperature, max_tokens=max_tokens) or ""


def _fallback_triage(pack: EvidencePack, errs: List[str]) -> TriageOutput:
    coverage = float(pack.coverage_summary.get("coverage_score") or 0.0)
    conflict = bool(pack.conflict_summary.get("has_conflict"))
    metadata_eid = str(pack.triage_features.get("metadata_evidence_id") or "")
    valid_ids = sorted(all_pack_evidence_ids(pack))
    top_level_ids = [metadata_eid] if metadata_eid in valid_ids else (valid_ids[:1] if valid_ids else [])

    uncertainty_reasons = ["structured_fallback_used"]
    if coverage < 0.38:
        uncertainty_reasons.append("low_coverage")
    if conflict:
        uncertainty_reasons.append("conflicting_evidence")
    uncertainty_reasons.extend(errs[:3])

    missing_information = []
    if float(pack.coverage_summary.get("components", {}).get("post_auth_correlation", 0.0)) < 1.0:
        missing_information.append("stronger corroboration for post-auth activity")
    if not pack.coverage_summary.get("has_outbound_or_ids"):
        missing_information.append("outbound or IDS corroboration")
    if not pack.entities.get("affected_user") or not pack.entities.get("affected_host"):
        missing_information.append("complete affected user/host attribution")

    ceiling = confidence_ceiling_for_coverage(coverage)
    confidence = min(0.45 if conflict else 0.55, ceiling)
    rationale = (
        "Defer because the model output could not be safely validated into the required evidence-based "
        "JSON shape, so a supported decision cannot be justified from the pack alone."
    )

    return TriageOutput(
        incident_id=pack.incident_id,
        decision="defer",
        confidence=round(confidence, 3),
        rationale=rationale,
        evidence_ids=top_level_ids,
        claims=[],
        missing_information=missing_information,
        uncertainty_reasons=uncertainty_reasons,
    )


def _normalize_triage_output(pack: EvidencePack, triage: TriageOutput) -> TriageOutput:
    valid_ids = all_pack_evidence_ids(pack)
    triage.evidence_ids = [eid for eid in dict.fromkeys(triage.evidence_ids) if eid in valid_ids]

    normalized_claims = []
    for claim in triage.claims:
        claim.text = " ".join((claim.text or "").split()).strip()
        claim.evidence_ids = [eid for eid in dict.fromkeys(claim.evidence_ids) if eid in valid_ids]
        if claim.text:
            normalized_claims.append(claim)
    triage.claims = normalized_claims

    if not triage.evidence_ids:
        claim_ids = []
        for claim in triage.claims:
            claim_ids.extend(claim.evidence_ids)
        if claim_ids:
            triage.evidence_ids = list(dict.fromkeys(claim_ids))

    metadata_eid = str(pack.triage_features.get("metadata_evidence_id") or "")
    if not triage.evidence_ids and metadata_eid in valid_ids:
        triage.evidence_ids = [metadata_eid]

    if triage.decision == "defer" and not triage.uncertainty_reasons:
        triage.uncertainty_reasons = ["insufficient_or_conflicting_evidence"]

    if not triage.rationale.strip():
        triage.rationale = (
            "The decision is based only on the evidence pack, with confidence constrained by coverage and "
            "any conflict indicators."
        )

    return triage


def run_evidence_constrained_triage(
    pack: EvidencePack,
    temperature: float = 0.15,
    max_tokens: int = 1200,
) -> Tuple[Optional[TriageOutput], str, List[str]]:
    """
    Returns (triage_output_or_none, raw_model_text, validation_errors).
    """
    if not is_llm_configured():
        return None, "", ["llm_not_configured"]

    messages = build_triage_messages(pack.to_dict())
    raw = _call_triage_llm(messages, temperature=temperature, max_tokens=max_tokens)
    parsed, errs = parse_triage_output(raw, pack.incident_id)
    if parsed is None:
        fallback = _fallback_triage(pack, errs)
        return fallback, raw, errs + ["structured_fallback_used"]
    parsed = _normalize_triage_output(pack, parsed)
    return parsed, raw, errs

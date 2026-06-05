"""End-to-end evidence triage workflow + optional baselines + metrics log."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from agent.triage_agent import run_evidence_constrained_triage
from decision.deferral_policy import apply_deferral_policy
from evaluation.baselines import rule_baseline_decision, vanilla_llm_baseline
from evaluation.metrics_logger import log_experiment_row
from evidence.evidence_models import TriageOutput, VerifierOutput
from evidence.evidence_pack_builder import all_pack_evidence_ids, build_evidence_pack
from utils.schema import Incident
from verification.consistency_checks import confidence_ceiling_for_coverage
from verification.verifier import verify_triage


def _normalize_triage_output(pack, triage: TriageOutput) -> TriageOutput:
    """Light normalization so realistic-but-noisy LLM outputs aren't rejected for formatting quirks."""
    valid_ids = all_pack_evidence_ids(pack)
    mapped = []
    for eid in triage.evidence_ids:
        e = str(eid).strip()
        if e == "triage_features":
            e = str(pack.triage_features.get("metadata_evidence_id") or e)
        if e in valid_ids:
            mapped.append(e)
    triage.evidence_ids = sorted(set(mapped))

    for c in triage.claims:
        cids = []
        for eid in c.evidence_ids:
            e = str(eid).strip()
            if e == "triage_features":
                e = str(pack.triage_features.get("metadata_evidence_id") or e)
            if e in valid_ids:
                cids.append(e)
        c.evidence_ids = sorted(set(cids))

    # Confidence calibration keeps decisions realistic for thin evidence packs.
    cov = float(pack.coverage_summary.get("coverage_score") or 0.0)
    ceiling = confidence_ceiling_for_coverage(cov)
    if triage.confidence > ceiling:
        triage.confidence = round(ceiling, 3)
        note = f"confidence_calibrated_to_coverage_ceiling:{ceiling:.2f}"
        if note not in triage.uncertainty_reasons:
            triage.uncertainty_reasons.append(note)
    return triage


def run_evidence_triage_workflow(
    incident: Incident,
    *,
    run_llm: bool = True,
    run_vanilla_baseline: bool = False,
    log_path: str | None = None,
) -> Dict[str, Any]:
    pack = build_evidence_pack(incident)
    triage = None
    triage_raw = ""
    parse_errs: List[str] = []

    if run_llm:
        triage, triage_raw, parse_errs = run_evidence_constrained_triage(pack)
        if triage is not None:
            triage = _normalize_triage_output(pack, triage)

    if triage is None:
        verifier = VerifierOutput(
            incident_id=pack.incident_id,
            is_valid=False,
            unsupported_claims=["triage_missing_or_invalid"],
            missing_citations=[],
            contradictions=parse_errs or ["no_triage"],
            coverage_assessment="n/a",
            confidence_assessment="n/a",
            recommended_final_action="defer",
        )
    else:
        verifier = verify_triage(pack, triage)

    final = apply_deferral_policy(pack, triage, verifier)
    rule_out = rule_baseline_decision(pack)

    vanilla_out: Optional[Dict[str, Any]] = None
    vanilla_raw = ""
    vanilla_errs: List[str] = []
    if run_vanilla_baseline:
        vanilla_out, vanilla_raw, vanilla_errs = vanilla_llm_baseline(
            incident.incident_id,
            incident.title,
            incident.summary or "",
            incident.severity,
        )

    row = {
        "incident_id": incident.incident_id,
        "method_final_decision": final.final_decision,
        "method_policy": final.policy_applied,
        "verifier_valid": verifier.is_valid,
        "rule_baseline_decision": rule_out.get("decision"),
        "vanilla_decision": (vanilla_out or {}).get("decision"),
        "coverage_score": pack.coverage_summary.get("coverage_score"),
        "strong_evidence": pack.coverage_summary.get("strong_evidence_count"),
    }
    log_experiment_row(row, path=log_path)

    return {
        "evidence_pack": pack.to_dict(),
        "triage": triage.to_dict() if triage else None,
        "triage_raw": triage_raw,
        "triage_parse_errors": parse_errs,
        "verifier": verifier.to_dict(),
        "final_decision": final.to_dict(),
        "baselines": {
            "rule": rule_out,
            "vanilla": vanilla_out,
            "vanilla_raw": vanilla_raw,
            "vanilla_errors": vanilla_errs,
        },
    }


def run_batch(incidents: List[Incident], **kwargs: Any) -> List[Dict[str, Any]]:
    return [run_evidence_triage_workflow(inc, **kwargs) for inc in incidents]

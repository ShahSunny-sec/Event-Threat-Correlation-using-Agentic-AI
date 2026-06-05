"""Rule and vanilla-LLM baselines for comparison experiments."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from agent.openai_client import chat_completion, is_llm_configured
from agent.output_parser import parse_vanilla_baseline
from agent.triage_prompts import build_vanilla_triage_messages
from evidence.evidence_models import EvidencePack


def rule_baseline_decision(pack: EvidencePack) -> Dict[str, Any]:
    """Deterministic close / escalate / defer from pack features only (no LLM)."""
    cov = float(pack.coverage_summary.get("coverage_score") or 0.0)
    strong = int(pack.coverage_summary.get("strong_evidence_count") or 0)
    has_conflict = bool(pack.conflict_summary.get("has_conflict"))
    crit = float(pack.triage_features.get("criticality_score") or 0.0)
    sev = str(pack.triage_features.get("severity") or "medium")

    if cov < 0.32 or has_conflict:
        return {
            "method": "rule_baseline",
            "decision": "defer",
            "confidence": 0.55,
            "rationale": "Low coverage or conflict flags — abstain.",
        }

    if strong >= 2 and crit >= 60 and sev in ("high", "critical") and not has_conflict:
        return {
            "method": "rule_baseline",
            "decision": "escalate",
            "confidence": min(0.5 + cov * 0.4, 0.88),
            "rationale": "Multiple strong evidence dimensions and elevated criticality.",
        }

    if strong <= 1 and cov < 0.55 and sev in ("low", "medium"):
        return {
            "method": "rule_baseline",
            "decision": "close",
            "confidence": 0.62,
            "rationale": "Limited corroboration — treat as non-escalated pending more data.",
        }

    return {
        "method": "rule_baseline",
        "decision": "defer",
        "confidence": 0.5,
        "rationale": "Ambiguous feature mix — abstain.",
    }


def vanilla_llm_baseline(
    incident_id: str, title: str, summary: str, severity: str
) -> Tuple[Optional[Dict[str, Any]], str, List[str]]:
    """Unconstrained small-context LLM triage (no evidence pack, no citations)."""
    if not is_llm_configured():
        return None, "", ["llm_not_configured"]
    messages = build_vanilla_triage_messages(incident_id, title, summary, severity)
    raw = chat_completion(messages, temperature=0.5, max_tokens=400) or ""
    parsed, errs = parse_vanilla_baseline(raw, incident_id)
    if parsed:
        parsed["method"] = "vanilla_llm_baseline"
    return parsed, raw, errs

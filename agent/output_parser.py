"""Parse and validate triage JSON from LLM output."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from evidence.evidence_models import Claim, TriageOutput


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    t = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", t, re.DOTALL)
    if fence:
        t = fence.group(1)
    try:
        obj = json.loads(t)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    start = t.find("{")
    end = t.rfind("}")
    if start >= 0 and end > start:
        try:
            obj = json.loads(t[start : end + 1])
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None
    return None


REQUIRED_KEYS = {
    "incident_id",
    "decision",
    "confidence",
    "rationale",
    "evidence_ids",
    "claims",
    "missing_information",
    "uncertainty_reasons",
}


def parse_triage_output(raw: str, expected_incident_id: str) -> Tuple[Optional[TriageOutput], List[str]]:
    errors: List[str] = []
    obj = _extract_json_object(raw)
    if obj is None:
        return None, ["parse_error: no valid JSON object"]

    missing = REQUIRED_KEYS - set(obj.keys())
    if missing:
        errors.append(f"missing_keys:{sorted(missing)}")

    decision = str(obj.get("decision") or "").lower().strip()
    if decision not in ("close", "escalate", "defer"):
        errors.append("invalid_decision")

    try:
        conf = float(obj.get("confidence"))
    except (TypeError, ValueError):
        conf = -1.0
        errors.append("invalid_confidence")
    if not (0.0 <= conf <= 1.0):
        if "invalid_confidence" not in errors:
            errors.append("confidence_out_of_range")

    claims_raw = obj.get("claims")
    claims: List[Claim] = []
    if not isinstance(claims_raw, list):
        errors.append("claims_not_list")
    else:
        for i, c in enumerate(claims_raw):
            if not isinstance(c, dict):
                errors.append(f"claim_{i}_not_object")
                continue
            if "text" not in c and "claim" in c:
                c = dict(c)
                c["text"] = c.get("claim")
            claims.append(Claim.from_dict(c))

    ev_ids = obj.get("evidence_ids")
    if isinstance(ev_ids, str):
        ev_ids = [ev_ids]
    if not isinstance(ev_ids, list):
        errors.append("evidence_ids_not_list")
        ev_ids_list: List[str] = []
    else:
        ev_ids_list = [str(x) for x in ev_ids]

    miss = obj.get("missing_information")
    if isinstance(miss, str):
        miss = [miss]
    if not isinstance(miss, list):
        miss = []
    unc = obj.get("uncertainty_reasons")
    if isinstance(unc, str):
        unc = [unc]
    if not isinstance(unc, list):
        unc = []

    if errors:
        return None, errors

    return (
        TriageOutput(
            incident_id=str(obj.get("incident_id") or expected_incident_id),
            decision=decision,  # type: ignore[arg-type]
            confidence=conf,
            rationale=str(obj.get("rationale") or ""),
            evidence_ids=ev_ids_list,
            claims=claims,
            missing_information=[str(x) for x in miss],
            uncertainty_reasons=[str(x) for x in unc],
        ),
        [],
    )


def parse_vanilla_baseline(raw: str, expected_incident_id: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    obj = _extract_json_object(raw)
    if obj is None:
        return None, ["parse_error"]
    errs: List[str] = []
    dec = str(obj.get("decision") or "").lower()
    if dec not in ("close", "escalate", "defer"):
        errs.append("invalid_decision")
    try:
        conf = float(obj.get("confidence", 0))
    except (TypeError, ValueError):
        conf = 0.0
        errs.append("bad_confidence")
    if errs:
        return None, errs
    return (
        {
            "incident_id": str(obj.get("incident_id") or expected_incident_id),
            "decision": dec,
            "confidence": conf,
            "rationale": str(obj.get("rationale") or ""),
            "notes": str(obj.get("notes") or ""),
        },
        [],
    )

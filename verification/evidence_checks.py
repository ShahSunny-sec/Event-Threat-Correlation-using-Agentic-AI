"""Deterministic checks: citations exist, claims cite pack evidence."""
from __future__ import annotations

from typing import List, Set

from evidence.evidence_models import EvidencePack, TriageOutput
from evidence.evidence_pack_builder import all_pack_evidence_ids


def unknown_evidence_ids(pack: EvidencePack, triage: TriageOutput) -> List[str]:
    valid = all_pack_evidence_ids(pack)
    bad: List[str] = []
    for eid in triage.evidence_ids:
        if eid not in valid:
            bad.append(eid)
    for c in triage.claims:
        for eid in c.evidence_ids:
            if eid not in valid:
                bad.append(eid)
    return sorted(set(bad))


def claims_missing_citations(triage: TriageOutput) -> List[str]:
    missing: List[str] = []
    for i, c in enumerate(triage.claims):
        text = (c.text or "").strip()
        if len(text) < 8:
            continue
        if not c.evidence_ids:
            missing.append(f"claim[{i}]:{text[:80]}")
    return missing


def top_level_evidence_ids_nonempty(triage: TriageOutput) -> bool:
    return len(triage.evidence_ids) > 0

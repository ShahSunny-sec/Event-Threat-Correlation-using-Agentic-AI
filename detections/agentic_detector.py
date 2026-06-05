from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from agent.openai_client import chat_completion, get_last_llm_error
from utils.config import DETECTION_LLM_MODEL
from utils.schema import DetectionResult, Event

_LAST_AGENTIC_STATUS: Dict[str, Any] = {
    "ok": False,
    "reason": "not_run",
    "detail": "",
}


def get_last_agentic_status() -> Dict[str, Any]:
    return dict(_LAST_AGENTIC_STATUS)


def _set_status(ok: bool, reason: str, detail: str = "") -> None:
    _LAST_AGENTIC_STATUS["ok"] = ok
    _LAST_AGENTIC_STATUS["reason"] = reason
    _LAST_AGENTIC_STATUS["detail"] = detail[:500]


def _call_detection_llm(messages: List[Dict[str, str]], temperature: float, max_tokens: int) -> str:
    """Try JSON-mode first; if empty, retry once without response_format."""
    response = chat_completion(
        messages,
        model=DETECTION_LLM_MODEL,
        temperature=temperature,
        max_tokens=max_tokens,
        response_format={"type": "json_object"},
    )
    if response:
        return response
    # Provider sometimes returns empty/unsupported behavior for JSON mode.
    response = chat_completion(
        messages,
        model=DETECTION_LLM_MODEL,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return response or ""


def _event_brief(e: Event) -> Dict[str, Any]:
    return {
        "event_id": e.event_id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "log_source": e.log_source,
        "event_type": e.event_type,
        "user": e.user,
        "host": e.host,
        "src_ip": e.src_ip,
        "dst_ip": e.dst_ip,
        "severity": e.severity,
        "raw_log": e.raw_log[:90],
    }


def _parse_json_obj(text: str) -> Dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Fallback: extract first JSON object block if model added wrappers/trailing text.
    start = text.find("{")
    if start == -1:
        raise json.JSONDecodeError("No JSON object start found", text, 0)
    depth = 0
    end = -1
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end == -1:
        raise json.JSONDecodeError("No complete JSON object found", text, start)
    return json.loads(text[start : end + 1])


def detect_with_agentic_ai(events: List[Event]) -> List[DetectionResult]:
    if not events:
        _set_status(False, "no_events", "Input event list is empty.")
        return []

    # Keep token usage low so agentic detection still works under tight quotas.
    payload = [_event_brief(e) for e in events[:30]]
    messages = [
        {
            "role": "system",
            "content": (
                "You are a SOC detection agent. Return strict JSON only with schema: "
                '{"detections":[{"name":"...","type":"...","description":"...",'
                '"severity":"low|medium|high|critical","confidence":0.0,'
                '"event_ids":["..."],"user":null,"host":null,"src_ip":null,"dst_ip":null,'
                '"risk_score":0.0,"tags":["..."]}]}. '
                "Infer likely attack activity from event sequence."
            ),
        },
        {"role": "user", "content": json.dumps({"events": payload})},
    ]
    # One retry with stricter JSON instruction reduces intermittent empty runs.
    response = _call_detection_llm(messages, temperature=0.2, max_tokens=700)
    if not response:
        print("[AGENTIC DETECTOR] empty model response on first attempt")
        retry_messages = [
            {
                "role": "system",
                "content": (
                    "Return JSON ONLY. Do not use markdown fences. "
                    "Schema: {\"detections\":[{\"name\":\"...\",\"type\":\"...\",\"description\":\"...\","
                    "\"severity\":\"low|medium|high|critical\",\"confidence\":0.0,"
                    "\"event_ids\":[\"...\"],\"user\":null,\"host\":null,\"src_ip\":null,\"dst_ip\":null,"
                    "\"risk_score\":0.0,\"tags\":[\"...\"]}]}"
                ),
            },
            {"role": "user", "content": json.dumps({"events": payload})},
        ]
        response = _call_detection_llm(retry_messages, temperature=0.1, max_tokens=700)
        if not response:
            print("[AGENTIC DETECTOR] empty model response on retry; trying reduced-payload fallback")
            time.sleep(0.6)
            tiny_payload = payload[:12]
            tiny_messages = [
                {
                    "role": "system",
                    "content": (
                        "You are a SOC detection agent. Return strict JSON only with key 'detections'. "
                        "Keep output concise and valid JSON object."
                    ),
                },
                {"role": "user", "content": json.dumps({"events": tiny_payload})},
            ]
            response = _call_detection_llm(tiny_messages, temperature=0.0, max_tokens=380)
            if not response:
                _set_status(
                    False,
                    "empty_response",
                    "Model returned no content on all retry tiers. "
                    + (get_last_llm_error() or "no_provider_detail"),
                )
                return []

    try:
        data = _parse_json_obj(response)
    except Exception as exc:
        print(f"[AGENTIC DETECTOR] json parse failed: {exc}")
        retry_messages = [
            {
                "role": "system",
                "content": (
                    "Your previous output was invalid JSON. "
                    "Return strict JSON only with key 'detections' as an array."
                ),
            },
            {"role": "user", "content": json.dumps({"events": payload})},
        ]
        response = _call_detection_llm(retry_messages, temperature=0.0, max_tokens=700)
        if not response:
            _set_status(False, "parse_failed", f"Initial parse failed ({exc}); retry response empty.")
            return []
        try:
            data = _parse_json_obj(response)
        except Exception as exc2:
            print(f"[AGENTIC DETECTOR] retry parse failed: {exc2}")
            _set_status(False, "parse_failed", f"Initial parse failed ({exc}); retry parse failed ({exc2}).")
            return []

    by_id = {e.event_id: e for e in events}
    out: List[DetectionResult] = []
    for d in data.get("detections", []):
        event_ids = [eid for eid in d.get("event_ids", []) if eid in by_id]
        matched = [by_id[eid] for eid in event_ids]
        first_seen = min((e.timestamp for e in matched if e.timestamp), default=None)
        last_seen = max((e.timestamp for e in matched if e.timestamp), default=None)
        out.append(
            DetectionResult(
                detection_type=d.get("type", "agentic_ai"),
                detection_name=d.get("name", "Agentic Detection"),
                description=d.get("description", "Generated by AI detection agent."),
                severity=str(d.get("severity", "medium")).lower(),
                confidence=float(d.get("confidence", 0.6) or 0.6),
                event_ids=event_ids,
                events=matched,
                first_seen=first_seen,
                last_seen=last_seen,
                user=d.get("user"),
                host=d.get("host"),
                src_ip=d.get("src_ip"),
                dst_ip=d.get("dst_ip"),
                risk_score=float(d.get("risk_score", 55.0) or 55.0),
                tags=[str(t) for t in d.get("tags", ["agentic-ai"])],
                metadata={"generator": "agentic_ai"},
            )
        )
    if not out:
        print("[AGENTIC DETECTOR] model returned zero detections")
        _set_status(False, "model_zero_detections", "Model returned valid JSON with an empty detections list.")
        return out
    _set_status(True, "ok", f"Detections generated: {len(out)}")
    return out

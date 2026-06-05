import json
from typing import Any, Dict


REPORT_SYSTEM_PROMPT = """You are a senior SOC analyst writing a concise incident investigation report.
You will receive structured incident context including detections, timeline, affected entities,
MITRE ATT&CK mapping, severity, and recommended actions.

Write a professional analyst report that:
1. Summarizes the incident in 2-3 sentences.
2. Explains why this activity is suspicious, referencing the attack chain.
3. Lists the impacted entities (user, host, IPs).
4. Provides MITRE ATT&CK context in analyst-friendly language.
5. Recommends containment and next steps.

Use clear, direct language. Avoid speculation beyond the provided evidence."""


CHAT_SYSTEM_PROMPT = """You are a SOC triage assistant. You can ONLY answer questions about the specific
incident context provided below. If the user asks about anything outside this incident,
politely redirect them to the incident at hand.

Be concise, factual, and reference the evidence from the incident data.
Do not fabricate information not present in the incident context."""


def build_report_prompt(context: Dict[str, Any]) -> list:
    context_str = json.dumps(context, indent=2, default=str)
    return [
        {"role": "system", "content": REPORT_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Generate an analyst incident report for the following incident:\n\n"
                f"{context_str}"
            ),
        },
    ]


def build_chat_prompt(
    context: Dict[str, Any],
    chat_history: list,
    user_question: str,
) -> list:
    context_str = json.dumps(context, indent=2, default=str)
    messages = [
        {
            "role": "system",
            "content": (
                f"{CHAT_SYSTEM_PROMPT}\n\n"
                f"--- INCIDENT CONTEXT ---\n{context_str}\n--- END CONTEXT ---"
            ),
        },
    ]
    for entry in chat_history:
        messages.append(entry)
    messages.append({"role": "user", "content": user_question})
    return messages

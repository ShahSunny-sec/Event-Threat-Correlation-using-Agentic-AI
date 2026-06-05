from typing import Any, Dict, List, Optional

from agent.openai_client import chat_completion
from agent.prompts import build_chat_prompt


def chat_about_incident(
    incident_context: Dict[str, Any],
    chat_history: List[dict],
    user_question: str,
) -> str:
    """Answer a user question grounded in the given incident context.

    Falls back to a deterministic answer if OpenAI is unavailable.
    """
    messages = build_chat_prompt(incident_context, chat_history, user_question)
    response = chat_completion(messages, temperature=0.3, max_tokens=1000)

    if response:
        return response

    return _fallback_chat(incident_context, user_question)


def _fallback_chat(ctx: Dict[str, Any], question: str) -> str:
    """Provide a simple keyword-based fallback for common questions."""
    q = question.lower()

    if any(w in q for w in ["severity", "critical", "score", "how severe", "how bad"]):
        return (
            f"This incident has severity **{ctx.get('severity', 'N/A').upper()}** "
            f"with a criticality score of **{ctx.get('criticality_score', 'N/A')}/100**. "
            f"The severity is based on the combination of a brute force attack, "
            f"successful credential compromise, and suspicious outbound activity"
            f"{' confirmed by IDS alerts' if ctx.get('has_ids_alert') else ''}."
        )

    if any(w in q for w in ["user", "who", "account", "affected"]):
        return (
            f"The primary affected user is **{ctx.get('affected_user', 'N/A')}** "
            f"on host **{ctx.get('affected_host', 'N/A')}**. "
            f"The attack originated from source IP **{ctx.get('primary_src_ip', 'N/A')}**."
        )

    if any(w in q for w in ["recommend", "action", "contain", "mitigat", "what should"]):
        actions = ctx.get("recommended_actions", [])
        if actions:
            action_list = "\n".join(f"- {a}" for a in actions)
            return f"Recommended actions:\n{action_list}"
        return "No specific recommendations are available for this incident."

    if any(w in q for w in ["mitre", "att&ck", "tactic", "technique"]):
        tactics = ", ".join(ctx.get("mitre_tactics", [])) or "None mapped"
        techniques = ", ".join(ctx.get("mitre_techniques", [])) or "None mapped"
        return f"**MITRE Tactics:** {tactics}\n**MITRE Techniques:** {techniques}"

    if any(w in q for w in ["timeline", "when", "sequence", "order"]):
        timeline = ctx.get("timeline", [])
        if timeline:
            entries = "\n".join(
                f"- {e['timestamp']} [{e['event_type']}] {e['description']}"
                for e in timeline
            )
            return f"Event timeline:\n{entries}"
        return "No timeline data available."

    if any(w in q for w in ["summary", "what happened", "describe", "explain"]):
        return ctx.get("summary", "No summary available for this incident.")

    return (
        "I can answer questions about this specific incident, such as:\n"
        "- What is the severity?\n"
        "- Which user is affected?\n"
        "- What actions are recommended?\n"
        "- What MITRE ATT&CK mappings apply?\n"
        "- What is the event timeline?\n\n"
        f"**Incident:** {ctx.get('title', 'N/A')}\n"
        f"(OpenAI is not available for free-form answers. "
        f"Please ask one of the suggested questions.)"
    )

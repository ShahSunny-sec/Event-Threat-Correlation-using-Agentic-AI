from typing import Any, Dict, Optional

from agent.openai_client import chat_completion
from agent.prompts import build_report_prompt


def generate_report(incident_context: Dict[str, Any]) -> Optional[str]:
    """Generate an analyst-style report using OpenAI.

    Returns the report text or None if the API call fails.
    """
    messages = build_report_prompt(incident_context)
    return chat_completion(messages, temperature=0.3, max_tokens=2500)

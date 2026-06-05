from typing import Any, Dict, List, Optional

from openai import OpenAI

from utils.config import LLM_API_KEY, LLM_BASE_URL, LLM_FALLBACK_MODELS, LLM_MODEL

_LAST_LLM_ERROR = ""


def _is_placeholder_api_key(key: str) -> bool:
    k = (key or "").strip().lower()
    if not k:
        return True
    placeholders = {
        "your-api-key-here",
        "your-groq-api-key-here",
        "your-openai-api-key-here",
        "changeme",
        "replace-me",
        "sk-your-key-here",
    }
    return k in placeholders


def is_llm_configured() -> bool:
    return bool(LLM_API_KEY) and not _is_placeholder_api_key(LLM_API_KEY)


def get_llm_client() -> Optional[OpenAI]:
    if not is_llm_configured():
        return None
    return OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)


def get_last_llm_error() -> str:
    return _LAST_LLM_ERROR


def chat_completion(
    messages: List[dict],
    model: Optional[str] = None,
    temperature: float = 0.4,
    max_tokens: int = 2000,
    response_format: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Call LLM chat completion (Groq / OpenAI compatible). Returns None on failure."""
    global _LAST_LLM_ERROR
    client = get_llm_client()
    if client is None:
        _LAST_LLM_ERROR = "llm_not_configured"
        return None
    primary = model or LLM_MODEL
    tried = []
    for m in [primary] + [x for x in LLM_FALLBACK_MODELS if x != primary]:
        tried.append(m)
        try:
            kwargs: Dict[str, Any] = {
                "model": m,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if response_format is not None:
                kwargs["response_format"] = response_format

            response = client.chat.completions.create(
                **kwargs,
            )
            return response.choices[0].message.content
        except Exception as exc:
            _LAST_LLM_ERROR = f"{m}: {exc}"
            print(f"[LLM ERROR:{m}] {exc}")
            continue
    print(f"[LLM ERROR] all models failed: {tried}")
    if not _LAST_LLM_ERROR:
        _LAST_LLM_ERROR = f"all_models_failed:{tried}"
    return None

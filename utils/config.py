import os
from pathlib import Path

from dotenv import load_dotenv

# Repo root (…/event_correlation_soc), so Streamlit still finds .env if cwd differs
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CWD = Path.cwd()


def _strip_secret(value: str) -> str:
    v = (value or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    return v


def _load_env_files() -> tuple[list[Path], Path | None]:
    """Load env vars from real local configuration files (merge, no override).

    Order: project `.env`, cwd `.env`, then `.env.local`.
    `override=False` means the first file wins for any given key; later files only fill gaps.
    """
    candidates = [
        _PROJECT_ROOT / ".env",
        _CWD / ".env",
        _PROJECT_ROOT / ".env.local",
        _CWD / ".env.local",
    ]
    loaded: list[Path] = []
    for path in candidates:
        if not path.is_file():
            continue
        load_dotenv(path, override=False)
        loaded.append(path)
    primary = loaded[0] if loaded else None
    return loaded, primary


ENV_FILES_LOADED, ENV_FILE_PRIMARY = _load_env_files()

_raw_groq = os.getenv("GROQ_API_KEY", "")
_raw_openai = os.getenv("OPENAI_API_KEY", "")
LLM_API_KEY = _strip_secret(_raw_groq or _raw_openai)
LLM_KEY_SOURCE = "GROQ_API_KEY" if _strip_secret(_raw_groq) else ("OPENAI_API_KEY" if _strip_secret(_raw_openai) else "")
LLM_MODEL = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
# Use a smaller default model for detection reliability/quota efficiency.
DETECTION_LLM_MODEL = os.getenv("DETECTION_LLM_MODEL", "llama-3.1-8b-instant")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
LLM_FALLBACK_MODELS = [
    m.strip()
    for m in os.getenv(
        "LLM_FALLBACK_MODELS",
        "llama-3.1-8b-instant,groq/compound-mini,qwen/qwen3-32b,openai/gpt-oss-20b",
    ).split(",")
    if m.strip()
]

FAILED_LOGIN_BURST_THRESHOLD = 5
FAILED_LOGIN_BURST_WINDOW_MINUTES = 10
SUCCESS_AFTER_FAILURE_WINDOW_MINUTES = 15
SUSPICIOUS_OUTBOUND_WINDOW_MINUTES = 30
INCIDENT_CORRELATION_WINDOW_MINUTES = 30

CRITICALITY_WEIGHTS = {
    "failed_login_burst": 25,
    "success_after_failures": 35,
    "suspicious_outbound": 30,
    "ids_alert_boost": 10,
}

SEVERITY_BANDS = [
    (0, 30, "low"),
    (30, 55, "medium"),
    (55, 75, "high"),
    (75, 101, "critical"),
]


# Optional threat-intel APIs (never commit real keys; use .env locally)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

# Optional GitHub live events fallback source
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
GITHUB_REPO = os.getenv("GITHUB_REPO", "").strip()  # format: owner/repo
GITHUB_RAW_FEED_URL = os.getenv("GITHUB_RAW_FEED_URL", "").strip()
GITHUB_RAW_FEED_FORMAT = os.getenv("GITHUB_RAW_FEED_FORMAT", "jsonl").strip()

# Optional Neo4j (Bolt) for knowledge graph visualization
NEO4J_URI = os.getenv("NEO4J_URI", "").strip()
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j").strip()
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "").strip()
NEO4J_BROWSER_URL = os.getenv("NEO4J_BROWSER_URL", "http://localhost:7474").strip()

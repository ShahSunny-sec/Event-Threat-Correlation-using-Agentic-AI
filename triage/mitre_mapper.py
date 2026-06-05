from typing import Dict, List, Tuple

from utils.constants import (
    DETECTION_FAILED_LOGIN_BURST,
    DETECTION_SUCCESS_AFTER_FAILURES,
    DETECTION_SUSPICIOUS_OUTBOUND,
    MITRE_TACTIC_COLLECTION,
    MITRE_TACTIC_COMMAND_AND_CONTROL,
    MITRE_TACTIC_CREDENTIAL_ACCESS,
    MITRE_TACTIC_DEFENSE_EVASION,
    MITRE_TACTIC_DISCOVERY,
    MITRE_TACTIC_EXECUTION,
    MITRE_TACTIC_EXFILTRATION,
    MITRE_TACTIC_IMPACT,
    MITRE_TACTIC_INITIAL_ACCESS,
    MITRE_TACTIC_LATERAL_MOVEMENT,
    MITRE_TACTIC_PERSISTENCE,
    MITRE_TACTIC_PRIVILEGE_ESCALATION,
    MITRE_TACTIC_RECONNAISSANCE,
    MITRE_TECHNIQUE_ACCOUNT_MANIPULATION,
    MITRE_TECHNIQUE_APPLICATION_LAYER_PROTOCOL,
    MITRE_TECHNIQUE_BRUTE_FORCE,
    MITRE_TECHNIQUE_CREATE_ACCOUNT,
    MITRE_TECHNIQUE_DATA_ENCRYPTED,
    MITRE_TECHNIQUE_DATA_STAGED,
    MITRE_TECHNIQUE_EXFIL_OVER_C2,
    MITRE_TECHNIQUE_EXFIL_WEB,
    MITRE_TECHNIQUE_EXPLOIT_PUBLIC,
    MITRE_TECHNIQUE_INHIBIT_RECOVERY,
    MITRE_TECHNIQUE_NETWORK_SCAN,
    MITRE_TECHNIQUE_OS_CRED_DUMPING,
    MITRE_TECHNIQUE_PROCESS_INJECTION,
    MITRE_TECHNIQUE_RDP,
    MITRE_TECHNIQUE_SMB_ADMIN,
    MITRE_TECHNIQUE_VALID_ACCOUNTS,
)
from utils.schema import Incident

# ---------------------------------------------------------------------------
# Primary lookup: detection_type string → [(tactic, technique), ...]
# Keys cover both the constants AND the free-form names the LLM commonly uses.
# ---------------------------------------------------------------------------
MITRE_MAP: Dict[str, List[Tuple[str, str]]] = {
    # ── original three ──────────────────────────────────────────────────────
    DETECTION_FAILED_LOGIN_BURST: [
        (MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_BRUTE_FORCE),
    ],
    DETECTION_SUCCESS_AFTER_FAILURES: [
        (MITRE_TACTIC_INITIAL_ACCESS,    MITRE_TECHNIQUE_VALID_ACCOUNTS),
        (MITRE_TACTIC_DEFENSE_EVASION,   MITRE_TECHNIQUE_VALID_ACCOUNTS),
    ],
    DETECTION_SUSPICIOUS_OUTBOUND: [
        (MITRE_TACTIC_COMMAND_AND_CONTROL, MITRE_TECHNIQUE_APPLICATION_LAYER_PROTOCOL),
        (MITRE_TACTIC_EXFILTRATION,        MITRE_TECHNIQUE_EXFIL_OVER_C2),
    ],

    # ── ransomware / encryption ──────────────────────────────────────────────
    "ransomware_activity": [
        (MITRE_TACTIC_IMPACT,  MITRE_TECHNIQUE_DATA_ENCRYPTED),
        (MITRE_TACTIC_IMPACT,  MITRE_TECHNIQUE_INHIBIT_RECOVERY),
    ],
    "ransomware": [
        (MITRE_TACTIC_IMPACT,  MITRE_TECHNIQUE_DATA_ENCRYPTED),
        (MITRE_TACTIC_IMPACT,  MITRE_TECHNIQUE_INHIBIT_RECOVERY),
    ],
    "file_encryption": [
        (MITRE_TACTIC_IMPACT,  MITRE_TECHNIQUE_DATA_ENCRYPTED),
    ],
    "shadow_copy_deletion": [
        (MITRE_TACTIC_IMPACT,  MITRE_TECHNIQUE_INHIBIT_RECOVERY),
    ],

    # ── credential access ────────────────────────────────────────────────────
    "credential_stuffing": [
        (MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_BRUTE_FORCE),
        (MITRE_TACTIC_INITIAL_ACCESS,    MITRE_TECHNIQUE_VALID_ACCOUNTS),
    ],
    "credential_dumping": [
        (MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_OS_CRED_DUMPING),
    ],
    "brute_force": [
        (MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_BRUTE_FORCE),
    ],
    "password_spray": [
        (MITRE_TACTIC_CREDENTIAL_ACCESS, MITRE_TECHNIQUE_BRUTE_FORCE),
    ],
    "account_takeover": [
        (MITRE_TACTIC_INITIAL_ACCESS,  MITRE_TECHNIQUE_VALID_ACCOUNTS),
        (MITRE_TACTIC_DEFENSE_EVASION, MITRE_TECHNIQUE_VALID_ACCOUNTS),
    ],

    # ── privilege escalation ─────────────────────────────────────────────────
    "privilege_escalation": [
        (MITRE_TACTIC_PRIVILEGE_ESCALATION, MITRE_TECHNIQUE_PROCESS_INJECTION),
    ],
    "privesc": [
        (MITRE_TACTIC_PRIVILEGE_ESCALATION, MITRE_TECHNIQUE_PROCESS_INJECTION),
    ],
    "scheduled_task_abuse": [
        (MITRE_TACTIC_PRIVILEGE_ESCALATION, MITRE_TECHNIQUE_PROCESS_INJECTION),
        (MITRE_TACTIC_PERSISTENCE,          MITRE_TECHNIQUE_ACCOUNT_MANIPULATION),
    ],

    # ── lateral movement ─────────────────────────────────────────────────────
    "lateral_movement": [
        (MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_SMB_ADMIN),
    ],
    "smb_lateral_movement": [
        (MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_SMB_ADMIN),
    ],
    "rdp_lateral_movement": [
        (MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_RDP),
    ],
    "ssh_lateral_movement": [
        (MITRE_TACTIC_LATERAL_MOVEMENT, MITRE_TECHNIQUE_RDP),
    ],

    # ── initial access / web exploitation ────────────────────────────────────
    "web_attack": [
        (MITRE_TACTIC_INITIAL_ACCESS, MITRE_TECHNIQUE_EXPLOIT_PUBLIC),
    ],
    "sql_injection": [
        (MITRE_TACTIC_INITIAL_ACCESS, MITRE_TECHNIQUE_EXPLOIT_PUBLIC),
    ],
    "rce": [
        (MITRE_TACTIC_INITIAL_ACCESS, MITRE_TECHNIQUE_EXPLOIT_PUBLIC),
        (MITRE_TACTIC_EXECUTION,      MITRE_TECHNIQUE_PROCESS_INJECTION),
    ],
    "web_shell": [
        (MITRE_TACTIC_INITIAL_ACCESS, MITRE_TECHNIQUE_EXPLOIT_PUBLIC),
        (MITRE_TACTIC_EXECUTION,      MITRE_TECHNIQUE_PROCESS_INJECTION),
    ],
    "file_upload_rce": [
        (MITRE_TACTIC_INITIAL_ACCESS, MITRE_TECHNIQUE_EXPLOIT_PUBLIC),
        (MITRE_TACTIC_EXECUTION,      MITRE_TECHNIQUE_PROCESS_INJECTION),
    ],

    # ── execution / reverse shell ─────────────────────────────────────────────
    "process_execution": [
        (MITRE_TACTIC_EXECUTION, MITRE_TECHNIQUE_PROCESS_INJECTION),
    ],
    "reverse_shell": [
        (MITRE_TACTIC_EXECUTION,           MITRE_TECHNIQUE_PROCESS_INJECTION),
        (MITRE_TACTIC_COMMAND_AND_CONTROL, MITRE_TECHNIQUE_APPLICATION_LAYER_PROTOCOL),
    ],
    "c2_communication": [
        (MITRE_TACTIC_COMMAND_AND_CONTROL, MITRE_TECHNIQUE_APPLICATION_LAYER_PROTOCOL),
    ],
    "c2_beacon": [
        (MITRE_TACTIC_COMMAND_AND_CONTROL, MITRE_TECHNIQUE_APPLICATION_LAYER_PROTOCOL),
    ],

    # ── discovery ─────────────────────────────────────────────────────────────
    "network_scan": [
        (MITRE_TACTIC_DISCOVERY, MITRE_TECHNIQUE_NETWORK_SCAN),
    ],
    "reconnaissance": [
        (MITRE_TACTIC_RECONNAISSANCE, MITRE_TECHNIQUE_NETWORK_SCAN),
    ],
    "port_scan": [
        (MITRE_TACTIC_DISCOVERY, MITRE_TECHNIQUE_NETWORK_SCAN),
    ],

    # ── collection / exfiltration ─────────────────────────────────────────────
    "data_staging": [
        (MITRE_TACTIC_COLLECTION,   MITRE_TECHNIQUE_DATA_STAGED),
    ],
    "data_exfiltration": [
        (MITRE_TACTIC_EXFILTRATION, MITRE_TECHNIQUE_EXFIL_WEB),
        (MITRE_TACTIC_COLLECTION,   MITRE_TECHNIQUE_DATA_STAGED),
    ],
    "insider_threat": [
        (MITRE_TACTIC_COLLECTION,   MITRE_TECHNIQUE_DATA_STAGED),
        (MITRE_TACTIC_EXFILTRATION, MITRE_TECHNIQUE_EXFIL_WEB),
    ],
    "large_data_transfer": [
        (MITRE_TACTIC_EXFILTRATION, MITRE_TECHNIQUE_EXFIL_WEB),
    ],
    "cloud_exfiltration": [
        (MITRE_TACTIC_EXFILTRATION, MITRE_TECHNIQUE_EXFIL_WEB),
    ],

    # ── persistence / account manipulation ───────────────────────────────────
    "account_manipulation": [
        (MITRE_TACTIC_PERSISTENCE, MITRE_TECHNIQUE_ACCOUNT_MANIPULATION),
        (MITRE_TACTIC_PERSISTENCE, MITRE_TECHNIQUE_CREATE_ACCOUNT),
    ],
    "backdoor_account": [
        (MITRE_TACTIC_PERSISTENCE, MITRE_TECHNIQUE_CREATE_ACCOUNT),
    ],
    "new_admin_account": [
        (MITRE_TACTIC_PERSISTENCE, MITRE_TECHNIQUE_ACCOUNT_MANIPULATION),
    ],
}


# ---------------------------------------------------------------------------
# Keyword-based normalisation: maps free-form LLM detection type/name/desc
# to one of the MITRE_MAP keys when there is no exact key match.
# ---------------------------------------------------------------------------
_KEYWORD_RULES: List[Tuple[List[str], str]] = [
    # ransomware
    (["ransomware", "file_encrypt", "shadow_cop", "vssadmin", ".locked", ".crypt"], "ransomware_activity"),
    # credential dumping
    (["lsass", "credential_dump", "mimikatz", "os_cred", "pass_the_hash"], "credential_dumping"),
    # credential stuffing / ATO
    (["credential_stuff", "account_takeover", "ato", "impossible_travel", "stuffing"], "credential_stuffing"),
    # brute force
    (["brute_force", "failed_login_burst", "login_burst", "password_spray"], "brute_force"),
    # success after failures
    (["success_after_fail", "successful_login_after", "valid_account",
      "credential_compromise", "compromised_account"], DETECTION_SUCCESS_AFTER_FAILURES),
    # privilege escalation
    (["privilege_escal", "privesc", "token_impersonat", "scheduled_task",
      "sudo_abuse", "uac_bypass", "elevation"], "privilege_escalation"),
    # lateral movement
    (["lateral_movement", "lateral", "smb_admin", "pass_the_hash",
      "admin_share", "wmi_exec", "psexec"], "lateral_movement"),
    # web attack / RCE / SQLi
    (["web_attack", "sql_inject", "sqli", "rce", "remote_code",
      "file_upload", "webshell", "web_shell", "path_traversal", "exploit_public"], "web_attack"),
    # reverse shell / C2 execution
    (["reverse_shell", "webshell_exec", "shell_spawn", "bash_reverse", "netcat"], "reverse_shell"),
    # C2 beacon / outbound
    (["c2", "c_and_c", "command_and_control", "callback", "beacon",
      "suspicious_outbound", "outbound_connection"], DETECTION_SUSPICIOUS_OUTBOUND),
    # data exfil
    (["data_exfil", "exfiltrat", "large_upload", "cloud_exfil",
      "insider", "data_theft", "bulk_download"], "data_exfiltration"),
    # data staging
    (["data_stag", "archive", "7zip", "7z_exe", "staging", "local_stag"], "data_staging"),
    # network scan / discovery
    (["network_scan", "port_scan", "nmap", "service_discovery", "host_discovery"], "network_scan"),
    # account manipulation / persistence
    (["account_manipulat", "backdoor_account", "new_account",
      "admin_group", "domain_admin", "group_add", "create_account"], "account_manipulation"),
]


def _normalized_detection_key(det) -> str:
    parts = [
        det.detection_type or "",
        det.detection_name or "",
        det.description or "",
        " ".join(det.tags or []),
    ]
    text = " ".join(parts).lower().replace("-", "_").replace(" ", "_")

    for keywords, canonical_key in _KEYWORD_RULES:
        if any(kw in text for kw in keywords):
            return canonical_key

    return det.detection_type


def map_to_mitre(incident: Incident) -> Tuple[List[str], List[str]]:
    """Map incident detections to MITRE ATT&CK tactics and techniques.

    Returns (tactics, techniques) as deduplicated lists.
    """
    tactics: List[str] = []
    techniques: List[str] = []

    for det in incident.detections:
        # 1. Try exact detection_type key
        mappings = MITRE_MAP.get(det.detection_type, [])
        # 2. Fallback: keyword normalisation
        if not mappings:
            mappings = MITRE_MAP.get(_normalized_detection_key(det), [])
        for tactic, technique in mappings:
            if tactic not in tactics:
                tactics.append(tactic)
            if technique not in techniques:
                techniques.append(technique)

    return tactics, techniques

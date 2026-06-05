EVENT_TYPE_AUTH_FAILURE = "authentication_failure"
EVENT_TYPE_AUTH_SUCCESS = "authentication_success"
EVENT_TYPE_NETWORK_OUTBOUND = "network_outbound"
EVENT_TYPE_IDS_ALERT = "ids_alert"
EVENT_TYPE_NETWORK_INBOUND = "network_inbound"

LOG_SOURCE_LINUX_AUTH = "linux_auth"
LOG_SOURCE_WINDOWS_AUTH = "windows_auth"
LOG_SOURCE_NETWORK_IDS = "network_ids"

DETECTION_FAILED_LOGIN_BURST = "failed_login_burst"
DETECTION_SUCCESS_AFTER_FAILURES = "success_after_failures"
DETECTION_SUSPICIOUS_OUTBOUND = "suspicious_outbound"

INCIDENT_TYPE_MULTI_STAGE = "multi_stage_attack"

DIRECTION_OUTBOUND = "outbound"
DIRECTION_INBOUND = "inbound"

ACTION_BLOCKED = "blocked"
ACTION_ALLOWED = "allowed"

MITRE_TACTIC_CREDENTIAL_ACCESS = "Credential Access"
MITRE_TACTIC_INITIAL_ACCESS = "Initial Access"
MITRE_TACTIC_DEFENSE_EVASION = "Defense Evasion"
MITRE_TACTIC_COMMAND_AND_CONTROL = "Command and Control"
MITRE_TACTIC_EXFILTRATION = "Exfiltration"

MITRE_TECHNIQUE_BRUTE_FORCE = "T1110 - Brute Force"
MITRE_TECHNIQUE_VALID_ACCOUNTS = "T1078 - Valid Accounts"
MITRE_TECHNIQUE_APPLICATION_LAYER_PROTOCOL = "T1071 - Application Layer Protocol"
MITRE_TECHNIQUE_EXFIL_OVER_C2 = "T1041 - Exfiltration Over C2 Channel"

SUSPICIOUS_PORTS = {443, 8080, 8443, 4444, 5555, 9001, 1234, 31337}
SUSPICIOUS_PROTOCOLS = {"tcp", "tls", "https"}

# ---------------------------------------------------------------------------
# Additional event types for full kill-chain scenarios
# ---------------------------------------------------------------------------
EVENT_TYPE_FILE_ACCESS          = "file_access"
EVENT_TYPE_PROCESS_EXEC         = "process_execution"
EVENT_TYPE_DNS_QUERY            = "dns_query"
EVENT_TYPE_WEB_ATTACK           = "web_attack"
EVENT_TYPE_PRIVILEGE_ESCALATION = "privilege_escalation"
EVENT_TYPE_LATERAL_MOVEMENT     = "lateral_movement"
EVENT_TYPE_DATA_STAGING         = "data_staging"
EVENT_TYPE_RANSOMWARE           = "ransomware_activity"
EVENT_TYPE_ACCOUNT_MANIPULATION = "account_manipulation"
EVENT_TYPE_NETWORK_SCAN         = "network_scan"

# Additional log sources
LOG_SOURCE_WINDOWS_SYSMON = "windows_sysmon"
LOG_SOURCE_WEB_WAF        = "web_waf"
LOG_SOURCE_ENDPOINT_EDR   = "endpoint_edr"
LOG_SOURCE_DNS            = "dns"
LOG_SOURCE_WINDOWS_AUTH   = "windows_auth"

# Additional MITRE tactics
MITRE_TACTIC_EXECUTION          = "Execution"
MITRE_TACTIC_PERSISTENCE        = "Persistence"
MITRE_TACTIC_PRIVILEGE_ESCALATION = "Privilege Escalation"
MITRE_TACTIC_DISCOVERY          = "Discovery"
MITRE_TACTIC_LATERAL_MOVEMENT   = "Lateral Movement"
MITRE_TACTIC_COLLECTION         = "Collection"
MITRE_TACTIC_IMPACT             = "Impact"
MITRE_TACTIC_RECONNAISSANCE     = "Reconnaissance"

# Additional MITRE techniques
MITRE_TECHNIQUE_PHISHING            = "T1566 - Phishing"
MITRE_TECHNIQUE_EXPLOIT_PUBLIC      = "T1190 - Exploit Public-Facing Application"
MITRE_TECHNIQUE_OS_CRED_DUMPING     = "T1003 - OS Credential Dumping"
MITRE_TECHNIQUE_PROCESS_INJECTION   = "T1055 - Process Injection"
MITRE_TECHNIQUE_SMB_ADMIN           = "T1021.002 - SMB/Windows Admin Shares"
MITRE_TECHNIQUE_RDP                 = "T1021.001 - Remote Desktop Protocol"
MITRE_TECHNIQUE_DATA_STAGED         = "T1074 - Data Staged"
MITRE_TECHNIQUE_EXFIL_WEB           = "T1048 - Exfiltration Over Alternative Protocol"
MITRE_TECHNIQUE_DATA_ENCRYPTED      = "T1486 - Data Encrypted for Impact"
MITRE_TECHNIQUE_ACCOUNT_MANIPULATION = "T1098 - Account Manipulation"
MITRE_TECHNIQUE_NETWORK_SCAN        = "T1046 - Network Service Discovery"
MITRE_TECHNIQUE_CREATE_ACCOUNT      = "T1136 - Create Account"
MITRE_TECHNIQUE_INHIBIT_RECOVERY    = "T1490 - Inhibit System Recovery"

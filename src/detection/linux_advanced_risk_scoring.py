import ipaddress

from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


LINUX_FINDING_BASE_SCORES = {
    "Suspicious Linux Process Execution Detected": 65,
    "Linux Reverse Shell Detected": 95,
    "Advanced Telnet Activity Detected": 60,
    "Linux SSH Persistence Activity Detected": 80,
    "Linux Audit Tampering Activity Detected": 90,
    "Linux Log Clearing Activity Detected": 90,
    "Suspicious Linux File Permission Change Detected": 75,
    "Linux Systemd Persistence Activity Detected": 80,
    "Linux Cron Persistence Activity Detected": 80,
}


PRIVILEGED_USERS = {
    "root",
}


HIGH_RISK_COMMAND_PATTERNS = {
    "/dev/tcp/",
    "nc -e",
    "netcat -e",
    "ncat --exec",
    "socat ",
    "auditctl -e 0",
    "history -c",
    "unset histfile",
    "chmod u+s",
    "chmod +s",
    "chmod 4755",
}


def calculate_advanced_linux_risk_score(
    finding: ThreatFinding,
    execution: LinuxProcessExecution,
) -> int:
    score = LINUX_FINDING_BASE_SCORES.get(finding.title,50,)

    if execution.user in PRIVILEGED_USERS:
        score += 5

    if _is_external_ip(execution.source_ip):
        score += 5

    searchable_text = execution.searchable_text()

    if any(pattern in searchable_text for pattern in HIGH_RISK_COMMAND_PATTERNS):
        score += 5

    return min(score, 100)


def _is_external_ip(value: str) -> bool:
    if not value:
        return False

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )
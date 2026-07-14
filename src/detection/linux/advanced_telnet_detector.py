from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


TELNET_PATTERNS = {
    "telnet",
    "/usr/bin/telnet",
    "telnetd",
    "in.telnetd",
    "telnet.service",
    "telnet.socket",
}


def detect_advanced_telnet_activity(
    executions: list[LinuxProcessExecution],
) -> list[ThreatFinding]:
    findings = []

    for execution in executions:
        searchable_text = execution.searchable_text()

        matched_patterns = {
            pattern
            for pattern in TELNET_PATTERNS
            if pattern in searchable_text
        }

        if not matched_patterns:
            continue

        severity = "high" if execution.source_ip else "medium"

        findings.append(
            ThreatFinding(
                title="Advanced Telnet Activity Detected",
                severity=severity,
                description=(
                    "Telnet-related Linux process or service activity "
                    "was detected. Matched patterns: "
                    f"{', '.join(sorted(matched_patterns))}. "
                    f"Command: {execution.command}"
                ),
                source="Linux Host Detection",
                ip=execution.source_ip,
                hostname=execution.hostname,
                port=23,
                recommendation=(
                    "Review Telnet usage and disable Telnet where possible. "
                    "Replace Telnet with SSH because Telnet traffic is not "
                    "encrypted."
                ),
            )
        )

    return findings
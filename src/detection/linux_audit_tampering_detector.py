from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


AUDIT_TAMPERING_PATTERNS = {
    "systemctl stop auditd",
    "systemctl disable auditd",
    "service auditd stop",
    "service auditd disable",
    "auditctl -e 0",
    "rm /etc/audit/audit.rules",
    "rm -f /etc/audit/audit.rules",
    "truncate /etc/audit/audit.rules",
    "> /etc/audit/audit.rules",
    "/etc/audit/rules.d/",
}

AUDIT_CONFIGURATION_PATHS = {
    "/etc/audit/audit.rules",
    "/etc/audit/rules.d/",
}


def detect_linux_audit_tampering(
    executions: list[LinuxProcessExecution],
) -> list[ThreatFinding]:
    findings = []

    for execution in executions:
        searchable_text = execution.searchable_text()

        matched_patterns = {
            pattern
            for pattern in AUDIT_TAMPERING_PATTERNS
            if pattern in searchable_text
        }

        if not matched_patterns:
            continue

        findings.append(
            ThreatFinding(
                title="Linux Audit Tampering Activity Detected",
                severity="critical",
                description=(
                    "Potential Linux audit subsystem tampering was detected. "
                    "Matched patterns: "
                    f"{', '.join(sorted(matched_patterns))}. "
                    f"Command: {execution.command}"
                ),
                source="Linux Host Detection",
                ip=execution.source_ip,
                hostname=execution.hostname,
                recommendation=(
                    "Investigate the audit configuration immediately. "
                    "Verify auditd service state, inspect audit rules for "
                    "unauthorized changes, review privileged user activity, "
                    "and preserve available forensic evidence."
                ),
            )
        )

    return findings
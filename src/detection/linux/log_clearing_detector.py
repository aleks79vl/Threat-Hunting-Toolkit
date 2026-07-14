from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


LOG_CLEARING_PATTERNS = {
    "rm /var/log/",
    "rm -f /var/log/",
    "rm -rf /var/log/",
    "truncate /var/log/",
    "shred /var/log/",
    "> /var/log/",
    "journalctl --vacuum-time",
    "journalctl --vacuum-size",
    "journalctl --rotate",
    "history -c",
    "history -w",
    "unset histfile",
    "histfile=/dev/null",
    "/dev/null > ~/.bash_history",
    "rm ~/.bash_history",
    "rm -f ~/.bash_history",
    "shred ~/.bash_history",
}


def detect_linux_log_clearing(
    executions: list[LinuxProcessExecution],
) -> list[ThreatFinding]:
    findings = []

    for execution in executions:
        searchable_text = execution.searchable_text()

        matched_patterns = {
            pattern
            for pattern in LOG_CLEARING_PATTERNS
            if pattern in searchable_text
        }

        if not matched_patterns:
            continue

        findings.append(
            ThreatFinding(
                title="Linux Log Clearing Activity Detected",
                severity="critical",
                description=(
                    "Potential Linux log or command history clearing "
                    "activity was detected. Matched patterns: "
                    f"{', '.join(sorted(matched_patterns))}. "
                    f"Command: {execution.command}"
                ),
                source="Linux Host Detection",
                ip=execution.source_ip,
                hostname=execution.hostname,
                recommendation=(
                    "Investigate the activity immediately, preserve "
                    "remaining forensic evidence, review privileged user "
                    "activity, inspect centralized logging sources, and "
                    "verify whether logs or shell history were removed."
                ),
            )
        )

    return findings
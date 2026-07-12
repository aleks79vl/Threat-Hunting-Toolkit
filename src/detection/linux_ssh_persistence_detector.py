from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


SSH_PERSISTENCE_PATTERNS = {
    "authorized_keys",
    ".ssh/authorized_keys",
    "ssh-copy-id",
    "permitrootlogin yes",
    "passwordauthentication yes",
    "systemctl enable ssh",
    "systemctl enable sshd",
}


def detect_linux_ssh_persistence(
    executions: list[LinuxProcessExecution],
) -> list[ThreatFinding]:
    findings = []

    for execution in executions:
        searchable_text = execution.searchable_text()

        matched_patterns = {
            pattern
            for pattern in SSH_PERSISTENCE_PATTERNS
            if pattern in searchable_text
        }

        if not matched_patterns:
            continue

        findings.append(
            ThreatFinding(
                title="Linux SSH Persistence Activity Detected",
                severity="high",
                description=(
                    "Potential SSH persistence activity was detected. "
                    "Matched patterns: "
                    f"{', '.join(sorted(matched_patterns))}. "
                    f"Command: {execution.command}"
                ),
                source="Linux Host Detection",
                ip=execution.source_ip,
                hostname=execution.hostname,
                recommendation=(
                    "Review SSH configuration changes and authorized keys. "
                    "Validate whether the activity was authorized, inspect "
                    "the affected user account, and remove unauthorized SSH "
                    "keys or insecure SSH configuration changes."
                ),
            )
        )

    return findings
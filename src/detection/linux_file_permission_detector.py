from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


SUSPICIOUS_PERMISSION_PATTERNS = {
    "chmod 777",
    "chmod -r 777",
    "chmod +s",
    "chmod u+s",
    "chmod g+s",
    "chmod 4755",
    "chmod 4777",
    "chmod 2755",
    "chmod 2777",
}

SENSITIVE_PATHS = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
}

ROOT_OWNERSHIP_PATTERNS = {
    "chown root ",
    "chown root:",
    "chown root:root",
}


def detect_suspicious_file_permissions(
    executions: list[LinuxProcessExecution],
) -> list[ThreatFinding]:
    findings = []

    for execution in executions:
        searchable_text = execution.searchable_text()

        permission_matches = {
            pattern
            for pattern in SUSPICIOUS_PERMISSION_PATTERNS
            if pattern in searchable_text
        }

        sensitive_path_matches = {
            path
            for path in SENSITIVE_PATHS
            if path in searchable_text
        }

        root_ownership_matches = {
            pattern
            for pattern in ROOT_OWNERSHIP_PATTERNS
            if pattern in searchable_text
        }

        suspicious_permission_change = bool(permission_matches)

        suspicious_root_ownership = bool(
            root_ownership_matches
            and sensitive_path_matches
        )

        if (
            not suspicious_permission_change
            and not suspicious_root_ownership
        ):
            continue

        matched_patterns = (
            permission_matches
            | root_ownership_matches
            | sensitive_path_matches
        )

        findings.append(
            ThreatFinding(
                title="Suspicious Linux File Permission Change Detected",
                severity="high",
                description=(
                    "Potentially dangerous Linux file permission or "
                    "ownership modification was detected. "
                    "Matched indicators: "
                    f"{', '.join(sorted(matched_patterns))}. "
                    f"Command: {execution.command}"
                ),
                source="Linux Host Detection",
                ip=execution.source_ip,
                hostname=execution.hostname,
                recommendation=(
                    "Review the affected file permissions and ownership, "
                    "verify whether the change was authorized, inspect for "
                    "SUID or SGID persistence, and restore secure file "
                    "permissions where required."
                ),
            )
        )

    return findings
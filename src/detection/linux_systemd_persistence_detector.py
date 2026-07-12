from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


SYSTEMD_PERSISTENCE_PATTERNS = {
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/lib/systemd/system/",
    "systemctl enable ",
    "systemctl enable --now ",
    "systemctl link ",
}

SYSTEMD_RELOAD_PATTERNS = {
    "systemctl daemon-reload",
    "systemctl daemon-reexec",
}

SERVICE_FILE_PATTERNS = {
    ".service",
    ".timer",
    ".socket",
}


def detect_linux_systemd_persistence(
    executions: list[LinuxProcessExecution],
) -> list[ThreatFinding]:
    findings = []

    for execution in executions:
        searchable_text = execution.searchable_text()

        persistence_matches = {pattern
            for pattern in SYSTEMD_PERSISTENCE_PATTERNS
            if pattern in searchable_text}

        reload_matches = {pattern
            for pattern in SYSTEMD_RELOAD_PATTERNS
            if pattern in searchable_text}

        service_file_matches = {pattern
            for pattern in SERVICE_FILE_PATTERNS
            if pattern in searchable_text}

        direct_persistence = bool(persistence_matches)

        suspicious_reload = bool(reload_matches and service_file_matches)

        if not direct_persistence and not suspicious_reload:
            continue

        matched_patterns = (persistence_matches | reload_matches | service_file_matches)

        findings.append(
            ThreatFinding(
                title="Linux Systemd Persistence Activity Detected",
                severity="high",
                description=(
                    "Potential systemd-based persistence activity was "
                    "detected. Matched indicators: "
                    f"{', '.join(sorted(matched_patterns))}. "
                    f"Command: {execution.command}"
                ),
                source="Linux Host Detection",
                ip=execution.source_ip,
                hostname=execution.hostname,
                recommendation=(
                    "Review the referenced systemd unit, inspect its ExecStart "
                    "command and file origin, verify whether the unit was "
                    "authorized, and disable or remove suspicious persistence."
                ),
            )
        )

    return findings
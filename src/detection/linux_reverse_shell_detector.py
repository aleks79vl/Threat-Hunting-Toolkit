from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


REVERSE_SHELL_PATTERNS = {
    "bash -i",
    "/bin/bash -i",
    "sh -i",
    "/bin/sh -i",
    "/dev/tcp/",
    "nc -e",
    "netcat -e",
    "ncat --exec",
    "socat ",
    "pty.spawn",
    "python -c",
    "python3 -c",
    "perl -e",
    "ruby -rsocket",
}


def detect_linux_reverse_shells(
    executions: list[LinuxProcessExecution],
) -> list[ThreatFinding]:
    findings = []

    for execution in executions:
        searchable_text = execution.searchable_text()

        matched_patterns = {
            pattern
            for pattern in REVERSE_SHELL_PATTERNS
            if pattern in searchable_text
        }

        if not matched_patterns:
            continue

        findings.append(
            ThreatFinding(
                title="Linux Reverse Shell Detected",
                severity="critical",
                description=(
                    "Potential Linux reverse shell command detected. "
                    f"Matched patterns: {', '.join(sorted(matched_patterns))}. "
                    f"Command: {execution.command}"
                ),
                source="Linux Host Detection",
                ip=execution.source_ip,
                hostname=execution.hostname,
                recommendation=(
                    "Investigate the command immediately, identify the "
                    "remote destination, isolate the host if needed, and "
                    "review related authentication and network activity."
                ),
            )
        )

    return findings
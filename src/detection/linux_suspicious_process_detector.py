from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


SUSPICIOUS_EXECUTABLES = {
    "bash",
    "/bin/bash",
    "sh",
    "/bin/sh",
    "python",
    "python3",
    "perl",
    "ruby",
    "nc",
    "netcat",
    "ncat",
    "socat",
}

SUSPICIOUS_PATHS = {
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
}

SUSPICIOUS_ARGUMENTS = {
    " -c ",
    " -e ",
    " --exec",
    "chmod +x",
}


def detect_suspicious_linux_processes(executions: list[LinuxProcessExecution],
) -> list[ThreatFinding]:
    findings = []

    for execution in executions:
        searchable_text = execution.searchable_text()
        executable = execution.executable

        executable_match = executable in SUSPICIOUS_EXECUTABLES
        path_match = any(path in searchable_text for path in SUSPICIOUS_PATHS)
        argument_match = any(arg in searchable_text for arg in SUSPICIOUS_ARGUMENTS)

        if not executable_match and not path_match and not argument_match:
            continue

        findings.append(
            ThreatFinding(
                title="Suspicious Linux Process Execution Detected",
                severity="high",
                description=(
                    "Suspicious Linux process execution detected. "
                    f"Command: {execution.command}"
                ),
                source="Linux Host Detection",
                ip=execution.source_ip,
                hostname=execution.hostname,
                recommendation=(
                    "Review the executed command, validate whether the "
                    "activity was authorized, and investigate possible "
                    "execution or post-exploitation behavior."
                ),
            )
        )

    return findings
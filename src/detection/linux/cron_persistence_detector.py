from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


CRON_PERSISTENCE_LOCATIONS = {
    "/etc/crontab",
    "/etc/cron.d/",
    "/var/spool/cron/",
    "/var/spool/cron/crontabs/",
}

CRON_MANAGEMENT_PATTERNS = {
    "crontab -e",
    "crontab -r",
    "crontab -u ",
}

CRON_SCHEDULE_PATTERNS = {
    "@reboot",
    "@hourly",
    "@daily",
    "@weekly",
    "@monthly",
}

SUSPICIOUS_CRON_PAYLOAD_PATTERNS = {
    "curl ",
    "wget ",
    "bash ",
    "/bin/bash",
    "sh ",
    "/bin/sh",
    "python ",
    "python3 ",
    "nc ",
    "netcat ",
    "ncat ",
    "socat ",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
}


def detect_linux_cron_persistence(
    executions: list[LinuxProcessExecution],
) -> list[ThreatFinding]:
    findings = []

    for execution in executions:
        searchable_text = execution.searchable_text()

        location_matches = {
            pattern
            for pattern in CRON_PERSISTENCE_LOCATIONS
            if pattern in searchable_text
        }

        management_matches = {
            pattern
            for pattern in CRON_MANAGEMENT_PATTERNS
            if pattern in searchable_text
        }

        schedule_matches = {
            pattern
            for pattern in CRON_SCHEDULE_PATTERNS
            if pattern in searchable_text
        }

        payload_matches = {
            pattern
            for pattern in SUSPICIOUS_CRON_PAYLOAD_PATTERNS
            if pattern in searchable_text
        }

        crontab_file_load = bool(
            execution.executable == "crontab"
            and execution.command
            and not any(
                option in execution.command
                for option in {" -e"," -l"," -r"," -u ",}))      

        direct_cron_modification = bool(location_matches or management_matches
            or crontab_file_load)
        suspicious_scheduled_payload = bool(schedule_matches and payload_matches)

        if (not direct_cron_modification and not suspicious_scheduled_payload):
            continue

        matched_patterns = (location_matches | management_matches
            | schedule_matches | payload_matches)

        findings.append(
            ThreatFinding(
                title="Linux Cron Persistence Activity Detected",
                severity="high",
                description=(
                    "Potential cron-based persistence activity was "
                    "detected. Matched indicators: "
                    f"{', '.join(sorted(matched_patterns))}. "
                    f"Command: {execution.command}"
                ),
                source="Linux Host Detection",
                ip=execution.source_ip,
                hostname=execution.hostname,
                recommendation=(
                    "Review the affected crontab or cron file, verify "
                    "whether the scheduled task was authorized, inspect "
                    "the referenced executable or script, and remove "
                    "unauthorized persistence."
                ),
            )
        )

    return findings
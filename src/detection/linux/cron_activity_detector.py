from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding


SUSPICIOUS_CRON_PATTERNS = {
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "curl",
    "wget",
    "nc ",
    "netcat",
    "bash",
    "sh ",
    "python",
    "python3",
}


def detect_suspicious_cron_activity(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    findings = []
    detected = set()

    for event in events:
        if event.service != "cron":
            continue

        message_lower = event.message.lower()

        matched_patterns = {
            pattern
            for pattern in SUSPICIOUS_CRON_PATTERNS
            if pattern in message_lower
        }

        if not matched_patterns:
            continue

        detection_key = (
            event.hostname,
            event.message,
        )

        if detection_key in detected:
            continue

        detected.add(detection_key)

        findings.append(
            ThreatFinding(
                title="Suspicious Cron Activity Detected",
                severity="high",
                description=(
                    f"Suspicious cron activity detected on host "
                    f"{event.hostname}. Matched patterns: "
                    f"{', '.join(sorted(matched_patterns))}."
                ),
                source="Linux Log Detection",
                hostname=event.hostname,
                recommendation=(
                    "Review the cron command and validate whether it is "
                    "authorized scheduled activity or persistence."
                ),
            )
        )

    return findings
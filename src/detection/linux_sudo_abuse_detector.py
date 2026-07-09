from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding


SUSPICIOUS_SUDO_PATTERNS = {
    "chmod 777",
    "useradd",
    "usermod",
    "visudo",
    "/etc/sudoers",
    "curl ",
    "wget ",
    "nc ",
    "netcat ",
    "bash",
    "/bin/sh",
    "python ",
    "python3 ",
}


def detect_sudo_abuse(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    findings = []
    detected = set()

    for event in events:
        if (
            event.service != "sudo"
            or event.action != "command"
        ):
            continue

        message_lower = event.message.lower()

        matched_patterns = {
            pattern
            for pattern in SUSPICIOUS_SUDO_PATTERNS
            if pattern in message_lower
        }

        if not matched_patterns:
            continue

        detection_key = (
            event.hostname,
            event.user,
            event.message,
        )

        if detection_key in detected:
            continue

        detected.add(detection_key)

        findings.append(
            ThreatFinding(
                title="Sudo Abuse Detected",
                severity="high",
                description=(
                    f"Suspicious sudo command activity detected "
                    f"for user {event.user} on host "
                    f"{event.hostname}. Matched patterns: "
                    f"{', '.join(sorted(matched_patterns))}."
                ),
                source="Linux Log Detection",
                hostname=event.hostname,
                recommendation=(
                    "Review the sudo command, validate whether the "
                    "privileged activity was authorized, and investigate "
                    "possible privilege abuse."
                ),
            )
        )

    return findings
from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding


PRIVILEGE_PATTERNS = {
    "sudo",
    "wheel",
    "admin",
    "root",
}


def detect_linux_user_privilege_activity(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        message_lower = event.message.lower()

        if event.action == "user_create":
            findings.append(
                ThreatFinding(
                    title="New Linux User Detected",
                    severity="medium",
                    description=(
                        f"New Linux user {event.user} was created "
                        f"on host {event.hostname}."
                    ),
                    source="Linux Log Detection",
                    hostname=event.hostname,
                    recommendation=(
                        "Verify whether the new user account was created "
                        "as part of authorized administrative activity."
                    ),
                )
            )

        if (
            "usermod" in message_lower
            or "gpasswd" in message_lower
            or "added user" in message_lower
        ) and any(
            pattern in message_lower
            for pattern in PRIVILEGE_PATTERNS
        ):
            findings.append(
                ThreatFinding(
                    title="Privileged User Modification Detected",
                    severity="critical",
                    description=(
                        f"Potential privileged user or group modification "
                        f"detected on host {event.hostname}: "
                        f"{event.message}"
                    ),
                    source="Linux Log Detection",
                    hostname=event.hostname,
                    recommendation=(
                        "Investigate privileged group membership changes "
                        "and validate whether the action was authorized."
                    ),
                )
            )

    return findings
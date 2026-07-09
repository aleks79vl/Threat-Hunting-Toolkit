from collections import Counter

from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding


FAILED_LOGIN_THRESHOLD = 3


def detect_successful_login_after_failures(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    failed_attempts = Counter()
    findings = []
    detected = set()

    for event in events:
        if (
            event.service == "ssh"
            and event.action == "authentication"
            and event.source_ip
        ):
            if event.status == "failed":
                failed_attempts[event.source_ip] += 1

            if (
                event.status == "success"
                and failed_attempts[event.source_ip] >= FAILED_LOGIN_THRESHOLD
                and event.source_ip not in detected
            ):
                detected.add(event.source_ip)

                findings.append(
                    ThreatFinding(
                        title="Successful Login After Failures Detected",
                        severity="critical",
                        description=(
                            f"Successful SSH login for user {event.user} "
                            f"from {event.source_ip} occurred after "
                            f"{failed_attempts[event.source_ip]} failed "
                            f"authentication attempts."
                        ),
                        source="Linux Log Detection",
                        ip=event.source_ip,
                        hostname=event.hostname,
                        port=22,
                        recommendation=(
                            "Investigate whether the account was compromised "
                            "after repeated failed authentication attempts."
                        ),
                    )
                )

    return findings
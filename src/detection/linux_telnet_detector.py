from collections import Counter

from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding


TELNET_REPEATED_ATTEMPTS_THRESHOLD = 5


def detect_telnet_activity(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    findings = []
    telnet_attempts = Counter()
    detected_sources = set()

    for event in events:
        if event.service != "telnet":
            continue

        if event.source_ip:
            telnet_attempts[event.source_ip] += 1

        if event.source_ip not in detected_sources:
            detected_sources.add(event.source_ip)

            findings.append(
                ThreatFinding(
                    title="Telnet Activity Detected",
                    severity="medium",
                    description=(
                        f"Telnet activity detected from "
                        f"{event.source_ip} on host {event.hostname}."
                    ),
                    source="Linux Log Detection",
                    ip=event.source_ip,
                    hostname=event.hostname,
                    port=23,
                    recommendation=(
                        "Review Telnet usage. Replace Telnet with SSH "
                        "where possible because Telnet is insecure."
                    ),
                )
            )

    for source_ip, count in telnet_attempts.items():
        if count >= TELNET_REPEATED_ATTEMPTS_THRESHOLD:
            findings.append(
                ThreatFinding(
                    title="Repeated Telnet Login Attempts Detected",
                    severity="high",
                    description=(
                        f"Source IP {source_ip} generated {count} "
                        f"Telnet connection or login attempts."
                    ),
                    source="Linux Log Detection",
                    ip=source_ip,
                    port=23,
                    recommendation=(
                        "Investigate repeated Telnet activity and block "
                        "unauthorized source IPs."
                    ),
                )
            )

    return findings
from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding


def detect_ssh_failed_logins(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if (
            event.service == "ssh"
            and event.action == "authentication"
            and event.status == "failed"
        ):
            findings.append(
                ThreatFinding(
                    title="Failed SSH Login Detected",
                    severity="medium",
                    description=(
                        f"Failed SSH login detected for user "
                        f"{event.user} from {event.source_ip}."
                    ),
                    source="Linux Log Detection",
                    ip=event.source_ip,
                    hostname=event.hostname,
                    port=22,
                    recommendation=(
                        "Review SSH authentication logs and verify whether "
                        "the source IP is authorized."
                    ),
                )
            )

    return findings
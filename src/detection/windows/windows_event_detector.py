from src.models.threat_finding import ThreatFinding
from src.utils.event_utils import SecurityEvent
from src.utils.event_time import normalize_event_time
from src.correlation.mitre_enrichment import (
    enrich_finding_with_mitre,
)


def detect_windows_events(
    events: list[SecurityEvent],
    source_timezone: str | None = None,
) -> list[ThreatFinding]:
    findings = []

    for event in events:

        event_time = normalize_event_time(
            event.timestamp,
            source_timezone=source_timezone,
        )

        if event.event_type == "4625":
            finding = ThreatFinding(
                title="Windows Failed Logon Detected",
                severity="medium",
                description=(
                    f"Failed logon detected for user "
                    f"{event.username} from IP {event.src_ip}."
                ),
                source="Windows Event Detector",
                ip=event.src_ip,
                hostname=event.hostname,
                recommendation="Review failed logon activity.",
                first_seen=event_time,
                last_seen=event_time,
            )

            finding = enrich_finding_with_mitre(
                finding
            )
            findings.append(finding)

        elif event.event_type == "4720":
            findings.append(
                ThreatFinding(
                    title="Windows User Account Created",
                    severity="high",
                    description=(
                        f"New user account created: "
                        f"{event.username}."
                    ),
                    source="Windows Event Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    recommendation=(
                        "Verify whether the account creation "
                        "was authorized."
                    ),
                    first_seen=event_time,
                    last_seen=event_time,
                )
            )

        elif event.event_type == "4732":
            findings.append(
                ThreatFinding(
                    title="User Added to Administrators Group",
                    severity="critical",
                    description=(
                        f"User {event.username} was added "
                        f"to a privileged group."
                    ),
                    source="Windows Event Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    recommendation=(
                        "Verify privileged group membership "
                        "changes immediately."
                    ),
                    first_seen=event_time,
                    last_seen=event_time,
                )
            )

        elif (
            event.event_type == "4688"
            and "powershell" in event.raw_event.lower()
        ):
            findings.append(
                ThreatFinding(
                    title="Suspicious PowerShell Process",
                    severity="high",
                    description=(
                        f"PowerShell activity detected "
                        f"for user {event.username}."
                    ),
                    source="Windows Event Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    recommendation=(
                        "Review PowerShell execution logs."
                    ),
                    first_seen=event_time,
                    last_seen=event_time,
                )
            )

        elif event.event_type == "1102":
            findings.append(
                ThreatFinding(
                    title="Windows Audit Log Cleared",
                    severity="critical",
                    description=(
                        f"Audit log was cleared by user "
                        f"{event.username}."
                    ),
                    source="Windows Event Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    recommendation=(
                        "Investigate possible defense evasion."
                    ),
                    first_seen=event_time,
                    last_seen=event_time,
                )
            )

    return findings

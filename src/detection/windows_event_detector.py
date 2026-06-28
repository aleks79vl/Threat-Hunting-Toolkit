from src.models.threat_finding import ThreatFinding
from src.utils.event_utils import SecurityEvent


def detect_windows_events(events: list[SecurityEvent]) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if event.event_type == "4625":
            findings.append(
                ThreatFinding(
                    title="Windows Failed Logon Detected",
                    severity="medium",
                    description=f"Failed logon detected for user {event.username} from IP {event.src_ip}.",
                    source="Windows Event Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    recommendation="Review failed logon activity."
                )
            )

        elif event.event_type == "4720":
            findings.append(
                ThreatFinding(
                    title="Windows User Account Created",
                    severity="high",
                    description=f"New user account created: {event.username}.",
                    source="Windows Event Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    recommendation="Verify whether the account creation was authorized."
                )
            )

        elif event.event_type == "4732":
            findings.append(
                ThreatFinding(
                    title="User Added to Administrators Group",
                    severity="critical",
                    description=f"User {event.username} was added to a privileged group.",
                    source="Windows Event Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    recommendation="Verify privileged group membership changes immediately."
                )
            )

        elif event.event_type == "4688" and "powershell" in event.raw_event.lower():
            findings.append(
                ThreatFinding(
                    title="Suspicious PowerShell Process",
                    severity="high",
                    description=f"PowerShell activity detected for user {event.username}.",
                    source="Windows Event Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    recommendation="Review PowerShell execution logs."
                )
            )

        elif event.event_type == "1102":
            findings.append(
                ThreatFinding(
                    title="Windows Audit Log Cleared",
                    severity="critical",
                    description=f"Audit log was cleared by user {event.username}.",
                    source="Windows Event Detector",
                    ip=event.src_ip,
                    hostname=event.hostname,
                    recommendation="Investigate possible defense evasion."
                )
            )

    return findings

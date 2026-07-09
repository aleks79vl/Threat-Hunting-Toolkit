from collections import Counter

from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding


SSH_BRUTE_FORCE_THRESHOLD = 5


def detect_ssh_bruteforce(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    failed_attempts = Counter()
    hostnames = {}

    for event in events:
        if (
            event.service == "ssh"
            and event.action == "authentication"
            and event.status == "failed"
            and event.source_ip
        ):
            failed_attempts[event.source_ip] += 1
            hostnames[event.source_ip] = event.hostname

    findings = []

    for source_ip, count in failed_attempts.items():
        if count >= SSH_BRUTE_FORCE_THRESHOLD:
            findings.append(
                ThreatFinding(
                    title="SSH Brute Force Detected",
                    severity="high",
                    description=(
                        f"Source IP {source_ip} generated {count} "
                        f"failed SSH authentication attempts."
                    ),
                    source="Linux Log Detection",
                    ip=source_ip,
                    hostname=hostnames.get(source_ip, ""),
                    port=22,
                    recommendation=(
                        "Block or investigate the source IP and review "
                        "SSH authentication logs for brute-force activity."
                    ),
                )
            )

    return findings
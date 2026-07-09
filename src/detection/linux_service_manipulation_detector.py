from collections import Counter

from src.models.linux_event import LinuxEvent
from src.models.threat_finding import ThreatFinding


REPEATED_SERVICE_MANIPULATION_THRESHOLD = 3

MONITORED_SERVICE_ACTIONS = {
    "service_stop",
    "service_restart",
}


def detect_linux_service_manipulation(
    events: list[LinuxEvent],
) -> list[ThreatFinding]:
    findings = []
    detected = set()
    manipulation_counter = Counter()
    hostnames = {}

    for event in events:
        if event.action not in MONITORED_SERVICE_ACTIONS:
            continue

        manipulation_key = (event.hostname,event.message,)

        if manipulation_key not in detected:
            detected.add(manipulation_key)

            findings.append(
                ThreatFinding(
                    title="Linux Service Manipulation Detected",
                    severity="medium",
                    description=(
                        f"Linux service lifecycle activity detected "
                        f"on host {event.hostname}: {event.message}"
                    ),
                    source="Linux Log Detection",
                    hostname=event.hostname,
                    recommendation=(
                        "Review the service lifecycle event and verify "
                        "whether the stop or restart action was authorized."
                    ),
                )
            )

        counter_key = (
            event.hostname,
            event.process,
        )

        manipulation_counter[counter_key] += 1
        hostnames[counter_key] = event.hostname

    for counter_key, count in manipulation_counter.items():
        if count < REPEATED_SERVICE_MANIPULATION_THRESHOLD:
            continue

        hostname, process = counter_key

        findings.append(
            ThreatFinding(
                title="Repeated Linux Service Manipulation Detected",
                severity="high",
                description=(
                    f"Repeated Linux service lifecycle activity was "
                    f"detected on host {hostname}. Process {process} "
                    f"generated {count} monitored service actions."
                ),
                source="Linux Log Detection",
                hostname=hostnames.get(counter_key, hostname),
                recommendation=(
                    "Investigate repeated service stop or restart activity "
                    "and validate whether automated or administrative "
                    "service manipulation is expected."
                ),
            )
        )

    return findings
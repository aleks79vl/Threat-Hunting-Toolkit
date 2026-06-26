from src.utils.event_utils import SecurityEvent


def correlate_threats(
    unknown_events: list[SecurityEvent],
    critical_events: list[SecurityEvent],
) -> list[dict]:

    correlated = []

    critical_map = {
        event.src_ip: event
        for event in critical_events
    }

    for unknown in unknown_events:

        if unknown.src_ip in critical_map:

            critical = critical_map[unknown.src_ip]

            correlated.append(
                {
                    "ip": unknown.src_ip,
                    "hostname": unknown.hostname,
                    "port": critical.dst_port,
                    "severity": "critical",
                    "reason": (
                        "Unknown host with exposed "
                        "critical service"
                    ),
                }
            )

    return correlated
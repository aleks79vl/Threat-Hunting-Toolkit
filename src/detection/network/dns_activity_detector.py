from collections import Counter, defaultdict

from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding
from src.utils.packet_time import normalize_packet_time


REPEATED_QUERY_THRESHOLD = 10
LONG_QUERY_THRESHOLD = 50
HIGH_QUERY_VOLUME_THRESHOLD = 100

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".work",
    ".gq",
    ".tk",
}


def _dns_time_range(
    events: list[NetworkEvent],
) -> tuple[str | None, str | None]:
    """Calculate the UTC time range of DNS packets."""

    if not events:
        return None, None

    earliest = None
    latest = None

    for event in events:
        packet_time = normalize_packet_time(event.timestamp)

        # Do not invent a complete time range when
        # any contributing packet has an invalid timestamp.
        if packet_time is None:
            return None, None

        if earliest is None or packet_time[0] < earliest[0]:
            earliest = packet_time

        if latest is None or packet_time[0] > latest[0]:
            latest = packet_time

    return earliest[1], latest[1]


def detect_suspicious_dns_activity(
    events: list[NetworkEvent],
) -> list[ThreatFinding]:
    """
    Detect suspicious DNS activity in normalized network events.
    Preserve source packet time ranges for aggregated findings.
    """

    dns_events = [
        event
        for event in events
        if event.dns_query
    ]

    if not dns_events:
        return []

    findings = []
    detected = set()

    query_counter = Counter(
        event.dns_query.lower()
        for event in dns_events
    )

    source_counter = Counter(
        event.src_ip
        for event in dns_events
        if event.src_ip
    )

    # Keep the packets contributing to each DNS query
    # and each source IP separately.
    events_by_query = defaultdict(list)
    events_by_source = defaultdict(list)

    for event in dns_events:
        events_by_query[event.dns_query.lower()].append(event)

        if event.src_ip:
            events_by_source[event.src_ip].append(event)

    for query, count in query_counter.items():

        first_seen, last_seen = _dns_time_range(
            events_by_query[query]
        )

        if count >= REPEATED_QUERY_THRESHOLD:
            detection_key = ("repeated_dns_query", query)

            if detection_key not in detected:
                detected.add(detection_key)

                findings.append(
                    ThreatFinding(
                        title="Repeated DNS Query Activity Detected",
                        severity="medium",
                        description=(
                            f"DNS query {query} was observed "
                            f"{count} times in network traffic."
                        ),
                        source="PCAP Network Detection",
                        recommendation=(
                            "Investigate repeated DNS activity and verify "
                            "whether the query pattern is expected."
                        ),
                        first_seen=first_seen,
                        last_seen=last_seen,
                    )
                )

        if len(query) >= LONG_QUERY_THRESHOLD:
            detection_key = ("long_dns_query", query)

            if detection_key not in detected:
                detected.add(detection_key)

                findings.append(
                    ThreatFinding(
                        title="Long DNS Query Detected",
                        severity="high",
                        description=(
                            f"Unusually long DNS query detected: {query}"
                        ),
                        source="PCAP Network Detection",
                        recommendation=(
                            "Investigate the DNS query for possible encoded "
                            "data or DNS tunneling behavior."
                        ),
                        first_seen=first_seen,
                        last_seen=last_seen,
                    )
                )

        if any(
            query.endswith(tld)
            for tld in SUSPICIOUS_TLDS
        ):
            detection_key = ("suspicious_dns_tld", query)

            if detection_key not in detected:
                detected.add(detection_key)

                findings.append(
                    ThreatFinding(
                        title="Suspicious DNS TLD Detected",
                        severity="medium",
                        description=(
                            f"DNS query uses a monitored suspicious "
                            f"top-level domain: {query}"
                        ),
                        source="PCAP Network Detection",
                        recommendation=(
                            "Review the queried domain and validate its "
                            "reputation and business purpose."
                        ),
                        first_seen=first_seen,
                        last_seen=last_seen,
                    )
                )

    for src_ip, count in source_counter.items():

        if count >= HIGH_QUERY_VOLUME_THRESHOLD:
            detection_key = ("high_dns_volume", src_ip)

            if detection_key not in detected:
                detected.add(detection_key)

                first_seen, last_seen = _dns_time_range(
                    events_by_source[src_ip]
                )

                findings.append(
                    ThreatFinding(
                        title="High DNS Query Volume Detected",
                        severity="high",
                        description=(
                            f"Source IP {src_ip} generated "
                            f"{count} DNS queries."
                        ),
                        source="PCAP Network Detection",
                        ip=src_ip,
                        recommendation=(
                            "Investigate the source host for abnormal DNS "
                            "behavior or possible automated communication."
                        ),
                        first_seen=first_seen,
                        last_seen=last_seen,
                    )
                )

    return findings
from urllib.parse import urlsplit

from src.intelligence.ioc_loader import get_iocs
from src.intelligence.ioc_comparison import ioc_matches
from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding
from src.utils.packet_time import normalize_packet_time


def detect_network_iocs(
    events: list[NetworkEvent],
) -> list[ThreatFinding]:
    """Detect IOC matches and preserve source-packet time ranges."""

    iocs = get_iocs()

    detected = {}
    observations = {}

    for event in events:
        event_time = normalize_packet_time(event.timestamp)

        searchable_values = {
            "ip": [
                event.src_ip,
                event.dst_ip,
            ],
            "domain": [
                event.dns_query,
                event.http_host,
            ],
            "url": [
                event.http_uri,
            ],
        }

        for ioc in iocs:
            ioc_type = ioc.ioc_type
            ioc_value = ioc.value

            for value in searchable_values.get(ioc_type, []):
                if not value:
                    continue

                if ioc_matches(ioc_type, ioc_value, value):
                    key = (
                        ioc.ioc_type,
                        ioc.value,
                        ioc.confidence,
                        ioc.source,
                        ioc.description,
                        event.src_ip,
                        event.dst_ip,
                        event.protocol,
                    )

                    if ioc_type == "url":
                        try:
                            target = urlsplit(ioc_value)
                            observed = urlsplit(value)
                        except ValueError:
                            pass
                        else:
                            # Path-only IOC without query dependency.
                            # Never persist the observed query string.
                            if (
                                ioc_value.startswith("/")
                                and not target.query
                                and not target.fragment
                                and observed.path
                            ):
                                observations.setdefault(
                                    key,
                                    {
                                        "field": "http_uri_path",
                                        "value": observed.path,
                                    },
                                )

                    elif ioc_type in ("ip", "domain"):
                        if ioc_type == "ip":
                            observed_field = (
                                "src_ip"
                                if value == event.src_ip
                                else "dst_ip"
                            )
                        else:
                            observed_field = (
                                "dns_query"
                                if value == event.dns_query
                                else "http_host"
                            )

                        observations.setdefault(
                            key,
                            {
                                "field": observed_field,
                                "value": value,
                            },
                        )

                    if key not in detected:
                        detected[key] = (
                            (event_time, event_time)
                            if event_time is not None
                            else None
                        )
                    elif detected[key] is not None:
                        if event_time is None:
                            detected[key] = None
                        else:
                            earliest, latest = detected[key]

                            if event_time[0] < earliest[0]:
                                earliest = event_time

                            if event_time[0] > latest[0]:
                                latest = event_time

                            detected[key] = (earliest, latest)

    findings = []

    for key in sorted(detected):
        (
            ioc_type,
            ioc_value,
            confidence,
            ioc_source,
            description,
            src_ip,
            dst_ip,
            protocol,
        ) = key

        time_range = detected[key]

        if time_range is None:
            first_seen = None
            last_seen = None
        else:
            first_seen = time_range[0][1]
            last_seen = time_range[1][1]

        finding = ThreatFinding(
            title="Network IOC Match Detected",
            severity="high",
            description=(
                f"Network traffic matched IOC {ioc_value} "
                f"of type {ioc_type}. "
                f"Context: {description}"
            ),
            source="PCAP Network Detection",
            ip=dst_ip or src_ip,
            recommendation=(
                "Investigate the matched IOC and verify whether the "
                "network communication is malicious or authorized."
            ),
            ioc_match=True,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            ioc_confidence=confidence,
            ioc_source=ioc_source,
            ioc_description=description,
            ioc_observation=observations.get(key, {}),
            first_seen=first_seen,
            last_seen=last_seen,
        )

        if ioc_type == "url" and key not in observations:
            # This identity records matching already performed
            # against the original NetworkEvent.
            # No observed URI or query is copied here.
            finding._core08_verified_url_ioc = (
                ioc_type,
                ioc_value,
                ioc_source,
            )

        findings.append(finding)

    return findings

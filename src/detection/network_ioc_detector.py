from src.intelligence.ioc_loader import get_iocs
from src.models.network_event import NetworkEvent
from src.models.threat_finding import ThreatFinding


def detect_network_iocs(
    events: list[NetworkEvent],
) -> list[ThreatFinding]:
    """
    Detect IOC matches in normalized network events.
    """

    iocs = get_iocs()
    detected = set()

    for event in events:
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
            ioc_value = ioc.value.lower()

            for value in searchable_values.get(ioc_type, []):
                if not value:
                    continue

                if ioc_value in value.lower():
                    detected.add(
                        (
                            ioc.ioc_type,
                            ioc.value,
                            ioc.confidence,
                            ioc.source,
                            ioc.description,
                            event.src_ip,
                            event.dst_ip,
                            event.protocol,
                        )
                    )

    findings = []

    for (
        ioc_type,
        ioc_value,
        confidence,
        ioc_source,
        description,
        src_ip,
        dst_ip,
        protocol,
    ) in sorted(detected):
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
        )

        findings.append(finding)

    return findings
from collections import defaultdict

from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


def detect_waf_security_events(
    events: list[WebInfrastructureEvent],
    *,
    minimum_blocks: int = 3,
    minimum_distinct_rules: int = 2,
) -> list[ThreatFinding]:
    if minimum_blocks < 1:
        raise ValueError(
            "minimum_blocks must be at least 1"
        )

    if minimum_distinct_rules < 1:
        raise ValueError(
            "minimum_distinct_rules must be at least 1"
        )

    blocked_events_by_ip = defaultdict(list)

    for event in events:
        if event.source != "waf_cdn":
            continue

        if event.metadata.get("waf_action") != "block":
            continue

        blocked_events_by_ip[event.client_ip].append(event)

    findings = []

    for client_ip, related_events in blocked_events_by_ip.items():
        rule_ids = {
            event.metadata.get("waf_rule_id", "")
            for event in related_events
            if event.metadata.get("waf_rule_id", "")
        }

        if len(related_events) >= minimum_blocks:
            findings.append(
                ThreatFinding(
                    title="Repeated WAF Blocks Detected",
                    severity="high",
                    description=(
                        f"IP address {client_ip!r} triggered "
                        f"{len(related_events)} WAF block events."
                    ),
                    source="WAF Security Detector",
                    ip=client_ip,
                    hostname=related_events[0].virtual_host,
                    recommendation=(
                        "Review the requests and consider blocking "
                        "the source IP or applying stricter rate limits."
                    ),
                )
            )

        if len(rule_ids) >= minimum_distinct_rules:
            findings.append(
                ThreatFinding(
                    title="Multiple WAF Rules Triggered",
                    severity="high",
                    description=(
                        f"IP address {client_ip!r} triggered "
                        f"{len(rule_ids)} distinct WAF rules."
                    ),
                    source="WAF Security Detector",
                    ip=client_ip,
                    hostname=related_events[0].virtual_host,
                    recommendation=(
                        "Investigate for multi-vector scanning or "
                        "attack activity and review affected routes."
                    ),
                )
            )

    return findings
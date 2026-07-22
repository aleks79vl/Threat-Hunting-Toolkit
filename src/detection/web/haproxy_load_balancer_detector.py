from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


def detect_haproxy_load_balancer_anomalies(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if event.source != "haproxy":
            continue

        termination_state = event.metadata.get(
            "termination_state",
            "",
        )

        backend_unavailable = (
            event.backend == "<NOSRV>"
            or termination_state.startswith("SC")
        )

        if backend_unavailable:
            findings.append(
                ThreatFinding(
                    title="HAProxy Backend Unavailable",
                    severity="high",
                    description=(
                        f"HAProxy could not route request "
                        f"{event.path!r} to an available backend. "
                        f"Backend: {event.backend!r}; termination "
                        f"state: {termination_state!r}."
                    ),
                    source="HAProxy Load Balancer Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host,
                    recommendation=(
                        "Review backend health checks, server "
                        "availability, and HAProxy failover settings."
                    ),
                )
            )
            continue

        if event.status_code < 500:
            continue

        findings.append(
            ThreatFinding(
                title="HAProxy Backend Server Error",
                severity="medium",
                description=(
                    f"Backend {event.backend!r} returned HTTP "
                    f"{event.status_code} for request "
                    f"{event.path!r}."
                ),
                source="HAProxy Load Balancer Detector",
                ip=event.client_ip,
                hostname=event.virtual_host,
                recommendation=(
                    "Investigate backend application errors and "
                    "consider temporarily removing unhealthy nodes "
                    "from the load-balancer pool."
                ),
            )
        )

    return findings
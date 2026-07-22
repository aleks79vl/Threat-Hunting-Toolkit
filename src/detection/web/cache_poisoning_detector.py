from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


def _get_header(
    headers: dict[str, str],
    name: str,
) -> str:
    for header_name, value in headers.items():
        if header_name.lower() == name.lower():
            return value

    return ""


def _is_shared_cacheable(
    response_headers: dict[str, str],
) -> bool:
    cache_control = _get_header(
        response_headers,
        "cache-control",
    ).lower()

    surrogate_control = _get_header(
        response_headers,
        "surrogate-control",
    ).lower()

    if "private" in cache_control or "no-store" in cache_control:
        return False

    return (
        "public" in cache_control
        or "s-maxage" in cache_control
        or "max-age" in surrogate_control
    )


def _normalize_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def detect_cache_poisoning_indicators(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        if event.method.upper() not in {"GET", "HEAD"}:
            continue

        if not _is_shared_cacheable(event.response_headers):
            continue

        forwarded_host = _get_header(
            event.request_headers,
            "x-forwarded-host",
        )

        if not forwarded_host:
            continue

        if _normalize_host(forwarded_host) == _normalize_host(
            event.host
        ):
            continue

        findings.append(
            ThreatFinding(
                title="Potential Web Cache Poisoning via Forwarded Host",
                severity="high",
                description=(
                    "A shared-cacheable response was generated for "
                    f"Host {event.host!r}, while the request supplied "
                    f"X-Forwarded-Host {forwarded_host!r}."
                ),
                source="Cache Poisoning Detector",
                ip=event.client_ip,
                hostname=event.virtual_host or event.host,
                port=event.server_port,
                recommendation=(
                    "Remove untrusted forwarded host headers and ensure "
                    "the cache key includes every header that affects "
                    "the generated response."
                ),
            )
        )

    return findings
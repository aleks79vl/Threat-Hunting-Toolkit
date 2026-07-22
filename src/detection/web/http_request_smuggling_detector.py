from src.models.threat_finding import ThreatFinding
from src.models.web_infrastructure_event import WebInfrastructureEvent


FRAMING_HEADER_NAMES = frozenset(
    {
        "content-length",
        "transfer-encoding",
    }
)


def detect_http_request_smuggling_indicators(
    events: list[WebInfrastructureEvent],
) -> list[ThreatFinding]:
    findings = []

    for event in events:
        headers = {
            name.lower(): value
            for name, value in event.request_headers.items()
        }

        content_length = headers.get("content-length")
        transfer_encoding = headers.get("transfer-encoding")

        if content_length and transfer_encoding:
            findings.append(
                ThreatFinding(
                    title="Ambiguous HTTP Request Framing Detected",
                    severity="high",
                    description=(
                        "The request contained both Content-Length and "
                        "Transfer-Encoding headers, which can cause "
                        "reverse proxies and backends to parse message "
                        "boundaries differently."
                    ),
                    source="HTTP Request Smuggling Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Reject requests containing both Content-Length "
                        "and Transfer-Encoding at the proxy boundary."
                    ),
                )
            )

        connection_value = headers.get("connection", "")
        connection_tokens = {
            token.strip().lower()
            for token in connection_value.split(",")
            if token.strip()
        }

        hidden_framing_headers = (
            connection_tokens & FRAMING_HEADER_NAMES
        )

        if hidden_framing_headers:
            header_list = ", ".join(
                sorted(hidden_framing_headers)
            )

            findings.append(
                ThreatFinding(
                    title="Framing Header Listed in Connection Header",
                    severity="high",
                    description=(
                        "The Connection header declared the following "
                        f"message-framing header(s) as hop-by-hop: "
                        f"{header_list}."
                    ),
                    source="HTTP Request Smuggling Detector",
                    ip=event.client_ip,
                    hostname=event.virtual_host or event.host,
                    port=event.server_port,
                    recommendation=(
                        "Reject Connection header values that reference "
                        "Content-Length or Transfer-Encoding."
                    ),
                )
            )

    return findings
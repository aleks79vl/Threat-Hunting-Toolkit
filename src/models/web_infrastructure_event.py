from dataclasses import asdict, dataclass, field

SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-api-key",
    }
)


def redact_sensitive_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: (
            "[REDACTED]"
            if name.lower() in SENSITIVE_HEADER_NAMES
            else value
        )
        for name, value in headers.items()
    }


@dataclass
class WebInfrastructureEvent:
    """
    Normalized event produced by a web-infrastructure log source.

    Supports Apache, Nginx, reverse proxy, load balancer,
    WAF/CDN and API gateway telemetry.
    """

    timestamp: str
    source: str
    client_ip: str
    method: str
    path: str
    status_code: int

    protocol: str = "HTTP/1.1"
    host: str = ""
    virtual_host: str = ""
    server_ip: str = ""
    server_port: int = 0

    request_id: str = ""
    trace_id: str = ""
    forwarded_for: list[str] = field(default_factory=list)

    upstream: str = ""
    backend: str = ""
    upstream_status: int | None = None

    response_size: int = 0
    response_time_ms: float | None = None

    user_agent: str = ""
    referer: str = ""
    tls_version: str = ""
    sni: str = ""
    websocket_upgrade: bool = False

    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)

    raw_event: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.request_headers = redact_sensitive_headers(
            self.request_headers)
        self.response_headers = redact_sensitive_headers(
            self.response_headers)

    def to_dict(self) -> dict:
        return asdict(self)
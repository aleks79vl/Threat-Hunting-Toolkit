import json

from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


def _as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _split_forwarded_for(value: str) -> list[str]:
    return [
        ip.strip()
        for ip in value.split(",")
        if ip.strip()
    ]


def parse_nginx_json_log(
    file_path: str,
) -> list[WebInfrastructureEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            request_time = _as_float(data.get("request_time"))
            response_time_ms = (
                request_time * 1000
                if request_time is not None
                else None
            )

            events.append(
                WebInfrastructureEvent(
                    timestamp=data.get("time", ""),
                    source="nginx",
                    client_ip=data.get("remote_addr", ""),
                    method=data.get("request_method", ""),
                    path=data.get("request_uri", ""),
                    status_code=_as_int(data.get("status")),
                    protocol=data.get(
                        "server_protocol",
                        "HTTP/1.1",
                    ),
                    host=data.get("host", ""),
                    virtual_host=data.get("server_name", ""),
                    server_ip=data.get("server_addr", ""),
                    server_port=_as_int(data.get("server_port")),
                    request_id=data.get("request_id", ""),
                    trace_id=data.get("trace_id", ""),
                    forwarded_for=_split_forwarded_for(
                        data.get("http_x_forwarded_for", "")
                    ),
                    upstream=data.get("upstream", ""),
                    backend=data.get("upstream_addr", ""),
                    upstream_status=_as_int(
                        data.get("upstream_status"),
                        default=0,
                    )
                    or None,
                    response_size=_as_int(data.get("bytes_sent")),
                    response_time_ms=response_time_ms,
                    user_agent=data.get("http_user_agent", ""),
                    referer=data.get("http_referer", ""),
                    tls_version=data.get("ssl_protocol", ""),
                    sni=data.get("ssl_server_name", ""),
                    websocket_upgrade=(
                        data.get("http_upgrade", "").lower()
                        == "websocket"
                    ),
                    raw_event=line.strip(),
                )
            )

    return events
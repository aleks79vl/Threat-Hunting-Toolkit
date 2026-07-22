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


def parse_api_gateway_log(
    file_path: str,
) -> list[WebInfrastructureEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            metadata = {
                "auth_status": data.get("auth_status", ""),
                "principal_id": data.get("principal_id", ""),
                "api_key_id": data.get("api_key_id", ""),
                "session_id_hash": data.get(
                "session_id_hash",
                "",
                ),
                "route_template": data.get(
                    "route_template",
                    "",
                ),
            }

            if data.get("rate_limit_remaining") is not None:
                metadata["rate_limit_remaining"] = _as_int(
                    data.get("rate_limit_remaining")
                )

            events.append(
                WebInfrastructureEvent(
                    timestamp=data.get("timestamp", ""),
                    source="api_gateway",
                    client_ip=data.get("client_ip", ""),
                    method=data.get("http_method", ""),
                    path=data.get("path", ""),
                    status_code=_as_int(data.get("status")),
                    protocol=data.get(
                        "protocol",
                        "HTTP/1.1",
                    ),
                    host=data.get("host", ""),
                    virtual_host=data.get("host", ""),
                    request_id=data.get("request_id", ""),
                    trace_id=data.get("trace_id", ""),
                    response_size=_as_int(
                        data.get("response_size")
                    ),
                    response_time_ms=_as_float(
                        data.get("response_latency_ms")
                    ),
                    user_agent=data.get("user_agent", ""),
                    metadata=metadata,
                )
            )

    return events
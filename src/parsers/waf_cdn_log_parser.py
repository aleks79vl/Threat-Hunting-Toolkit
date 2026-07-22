import json

from src.models.web_infrastructure_event import (
    WebInfrastructureEvent,
)


def _as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_waf_cdn_log(
    file_path: str,
) -> list[WebInfrastructureEvent]:
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            events.append(
                WebInfrastructureEvent(
                    timestamp=data.get("timestamp", ""),
                    source="waf_cdn",
                    client_ip=data.get("client_ip", ""),
                    method=data.get("method", ""),
                    path=data.get("path", ""),
                    status_code=_as_int(
                        data.get("status_code")
                    ),
                    protocol=data.get(
                        "protocol",
                        "HTTP/1.1",
                    ),
                    host=data.get("host", ""),
                    virtual_host=data.get("host", ""),
                    request_id=data.get("request_id", ""),
                    trace_id=data.get("trace_id", ""),
                    user_agent=data.get("user_agent", ""),
                    tls_version=data.get("tls_version", ""),
                    sni=data.get("sni", ""),
                    metadata={
                        "provider": data.get("provider", ""),
                        "waf_action": data.get("action", ""),
                        "waf_rule_id": data.get("rule_id", ""),
                        "waf_rule_name": data.get(
                            "rule_name",
                            "",
                        ),
                        "waf_rule_category": data.get(
                            "rule_category",
                            "",
                        ),
                    },
                )
            )

    return events
import json

import pytest

from src.parsers.nginx_json_log_parser import (
    parse_nginx_json_log,
)

from src.parsers.apache_access_log_parser import (
    parse_apache_access_log,
    parse_apache_vhost_access_log,
)
from src.parsers.haproxy_log_parser import (
    parse_haproxy_http_log,
)
from src.parsers.apache_error_log_parser import (
    parse_apache_error_log,
)
from src.parsers.nginx_error_log_parser import (
    parse_nginx_error_log,
)
from src.parsers.waf_cdn_log_parser import (
    parse_waf_cdn_log,
)


SYNTHETIC_SECRET = "SEC_API_01_SYNTHETIC_NOT_REAL_7c82"


@pytest.mark.parametrize(
    "sensitive_field",
    [
        "api_key_id",
        "access_token",
        "x-api-key",
    ],
)
def test_nginx_raw_event_redacts_sensitive_extra_fields(
    tmp_path,
    sensitive_field,
):
    payload = {
        "time": "2026-11-17T07:00:00Z",
        "remote_addr": "198.51.100.10",
        "request_method": "GET",
        "request_uri": "/health",
        "status": 200,
        "host": "example.test",
        sensitive_field: SYNTHETIC_SECRET,
    }

    path = tmp_path / "nginx.jsonl"
    path.write_text(
        json.dumps(payload) + "\n",
        encoding="utf-8",
    )

    events = parse_nginx_json_log(str(path))

    assert len(events) == 1

    raw_event = events[0].raw_event

    assert SYNTHETIC_SECRET not in raw_event
    assert (
        json.loads(raw_event)[sensitive_field]
        == "[REDACTED]"
    )


def test_nginx_raw_event_redacts_api_key_in_request_uri(
    tmp_path,
):
    payload = {
        "time": "2026-11-17T07:00:00Z",
        "remote_addr": "198.51.100.10",
        "request_method": "GET",
        "request_uri": (
            "/api?api_key=" + SYNTHETIC_SECRET
        ),
        "status": 200,
        "host": "example.test",
    }

    path = tmp_path / "nginx.jsonl"
    path.write_text(
        json.dumps(payload) + "\n",
        encoding="utf-8",
    )

    events = parse_nginx_json_log(str(path))

    assert len(events) == 1

    assert SYNTHETIC_SECRET not in events[0].raw_event
    assert "api_key=[REDACTED]" in events[0].raw_event

    assert SYNTHETIC_SECRET not in events[0].path

    assert SYNTHETIC_SECRET not in json.dumps(
        events[0].to_dict()
    )


@pytest.mark.parametrize(
    ("source_field", "event_field"),
    [
        ("http_referer", "referer"),
        ("http_user_agent", "user_agent"),
    ],
)
def test_nginx_event_fields_redact_embedded_credentials(
    tmp_path,
    source_field,
    event_field,
):
    payload = {
        "time": "2026-11-17T07:00:00Z",
        "remote_addr": "198.51.100.10",
        "request_method": "GET",
        "request_uri": "/health",
        "status": 200,
        "host": "example.test",
        source_field: (
            f"https://example.test/api?api_key={SYNTHETIC_SECRET}"
        ),
    }

    path = tmp_path / "nginx_sensitive_fields.jsonl"
    path.write_text(
        json.dumps(payload) + "\n",
        encoding="utf-8",
    )

    events = parse_nginx_json_log(str(path))

    assert len(events) == 1

    event = events[0]
    field_value = getattr(event, event_field)

    assert SYNTHETIC_SECRET not in field_value
    assert SYNTHETIC_SECRET not in json.dumps(event.to_dict())


@pytest.mark.parametrize(
    "parser_type",
    ["apache_access", "apache_vhost", "haproxy"],
)
def test_web_parsers_do_not_retain_credentials(
    tmp_path,
    parser_type,
):
    secret = "SEC_API_01_PARSER_NOT_REAL_5e82"
    uri = f"/api/test?api_key={secret}"

    apache_record = (
        "198.51.100.10 - - "
        "[17/Nov/2026:20:00:00 +0200] "
        f'"GET {uri} HTTP/1.1" 200 123 '
        f'"https://example.test/?api_key={secret}" '
        f'"TestAgent api_key={secret}"'
    )

    if parser_type == "apache_access":
        record = apache_record
        parser = parse_apache_access_log

    elif parser_type == "apache_vhost":
        record = "example.test " + apache_record
        parser = parse_apache_vhost_access_log

    else:
        record = (
            "198.51.100.10:54321 "
            "[17/Nov/2026:20:00:00.000] "
            "frontend backend/server "
            "0/0/0/0/1 200 123 - - ---- "
            f'"GET {uri} HTTP/1.1"'
        )
        parser = parse_haproxy_http_log

    input_path = tmp_path / "security_test.log"
    input_path.write_text(
        record + "\n",
        encoding="utf-8",
    )

    events = parser(str(input_path))

    assert len(events) == 1

    event = events[0]

    checked_fields = (
        "path",
        "referer",
        "user_agent",
        "raw_event",
    )

    leaking_fields = [
        field_name
        for field_name in checked_fields
        if secret in getattr(event, field_name)
    ]

    assert not leaking_fields, (
        f"Credential leaked into: {leaking_fields}"
    )

    assert secret not in json.dumps(event.to_dict())


@pytest.mark.parametrize(
    "parser_type",
    ["apache_error", "nginx_error", "waf_cdn"],
)
def test_remaining_web_parsers_do_not_retain_credentials(
    tmp_path,
    parser_type,
):
    secret = "SEC_API_01_ERROR_WAF_NOT_REAL_8c43"
    uri = f"/api/test?api_key={secret}"

    if parser_type == "apache_error":
        record = (
            "[Tue Nov 17 21:25:00.000000 2026] "
            "[core:error] "
            "[pid 123] "
            "[client 198.51.100.10:443] "
            f"Authentication failed api_key={secret}"
        )
        parser = parse_apache_error_log

    elif parser_type == "nginx_error":
        record = (
            "2026/11/17 21:25:00 [error] "
            "123#0: *1 "
            f"Authentication failed api_key={secret}, "
            "client: 198.51.100.10, "
            "server: example.test, "
            f'request: "GET {uri} HTTP/1.1", '
            'host: "example.test"'
        )
        parser = parse_nginx_error_log

    else:
        payload = {
            "timestamp": "2026-11-17T21:25:00Z",
            "client_ip": "198.51.100.10",
            "method": "GET",
            "path": uri,
            "status_code": 403,
            "host": "example.test",
            "user_agent": f"TestAgent api_key={secret}",
            "provider": "test_waf",
            "action": "block",
            "rule_id": "1001",
            "rule_name": f"Blocked api_key={secret}",
            "rule_category": "authentication",
            "request_headers": {
                "X-API-Key": secret,
            },
        }
        record = json.dumps(payload)
        parser = parse_waf_cdn_log

    input_path = tmp_path / "security_parser.log"
    input_path.write_text(
        record + "\n",
        encoding="utf-8",
    )

    events = parser(str(input_path))

    assert len(events) == 1

    event = events[0]
    serialized_event = event.to_dict()

    leaking_fields = [
        field_name
        for field_name, value in serialized_event.items()
        if secret in json.dumps(
            value,
            ensure_ascii=False,
        )
    ]

    assert not leaking_fields, (
        f"{parser_type} leaked credentials into "
        f"fields: {leaking_fields}"
    )

    assert secret not in json.dumps(
        serialized_event,
        ensure_ascii=False,
    )


@pytest.mark.parametrize(
    "credential_fragment",
    [
        f"X-API-Key: {SYNTHETIC_SECRET}",
        f"Authorization: Basic {SYNTHETIC_SECRET}",
    ],
)
def test_apache_error_raw_event_masks_header_credentials(
    tmp_path,
    credential_fragment,
):
    record = (
        "[Tue Nov 17 21:25:00.000000 2026] "
        "[core:error] "
        "[pid 123] "
        "[client 198.51.100.10:443] "
        f"Authentication failed {credential_fragment}"
    )

    path = tmp_path / "apache_error_credentials.log"
    path.write_text(record + "\n", encoding="utf-8")

    events = parse_apache_error_log(str(path))

    assert len(events) == 1

    assert SYNTHETIC_SECRET not in events[0].raw_event
    assert SYNTHETIC_SECRET not in json.dumps(
        events[0].to_dict()
    )

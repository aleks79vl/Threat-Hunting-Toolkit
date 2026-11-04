import json
import pytest

from src.parsers.nginx_json_log_parser import (
    parse_nginx_json_log,
)
from src.parsers.parser_diagnostics import ParserDiagnostics


def test_parse_nginx_json_log_returns_valid_events():
    events = parse_nginx_json_log(
        "data/raw/web/nginx_access.jsonl"
    )

    assert len(events) == 2


def test_nginx_event_contains_infrastructure_fields():
    event = parse_nginx_json_log(
        "data/raw/web/nginx_access.jsonl"
    )[0]

    assert event.source == "nginx"
    assert event.request_id == "req-001"
    assert event.trace_id == "trace-001"
    assert event.virtual_host == "api.example.com"
    assert event.upstream == "users_backend"
    assert event.backend == "10.0.1.15:8080"
    assert event.response_size == 2048
    assert event.response_time_ms == 125.0
    assert event.forwarded_for == [
        "198.51.100.10",
        "10.0.0.5",
    ]


def test_nginx_event_detects_websocket_upgrade():
    event = parse_nginx_json_log(
        "data/raw/web/nginx_access.jsonl"
    )[1]

    assert event.websocket_upgrade is True
    assert event.status_code == 101
    assert event.tls_version == "TLSv1.3"


def test_nginx_parser_preserves_request_and_response_headers(tmp_path):
    log_file = tmp_path / "nginx_headers.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/news",'
        '"status":200,'
        '"host":"example.com",'
        '"request_headers":{"X-Original-URL":"/admin"},'
        '"response_headers":{"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(str(log_file))

    assert len(events) == 1
    assert events[0].request_headers == {
        "X-Original-URL": "/admin",
    }
    assert events[0].response_headers == {
        "Cache-Control": "public, max-age=300",
    }


def test_nginx_parser_redacts_sensitive_headers(tmp_path):
    log_file = tmp_path / "nginx_sensitive_headers.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"request_headers":{'
        '"Authorization":"Bearer secret-token",'
        '"Cookie":"session=secret-value",'
        '"X-Original-URL":"/admin"},'
        '"response_headers":{'
        '"Set-Cookie":"session=another-secret",'
        '"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(str(log_file))

    assert len(events) == 1

    assert events[0].request_headers["Authorization"] == "[REDACTED]"
    assert events[0].request_headers["Cookie"] == "[REDACTED]"
    assert events[0].response_headers["Set-Cookie"] == "[REDACTED]"

    assert events[0].request_headers["X-Original-URL"] == "/admin"
    assert (
        events[0].response_headers["Cache-Control"]
        == "public, max-age=300"
    )


def test_nginx_parser_handles_invalid_header_types(tmp_path):
    log_file = tmp_path / "nginx_invalid_headers.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"request_headers":["invalid", "headers"],'
        '"response_headers":{"Cache-Control":"no-store"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(log_file)

    assert len(events) == 1
    assert events[0].request_headers == {}
    assert events[0].response_headers == {
        "Cache-Control": "no-store",
    }


def test_nginx_parser_filters_invalid_header_values(tmp_path):
    log_file = tmp_path / "nginx_invalid_header_values.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"request_headers":{'
        '"X-Original-URL":["/admin"],'
        '"Accept":"application/json"},'
        '"response_headers":{'
        '"Cache-Control":null,'
        '"X-Trace-ID":"trace-123"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(log_file)

    assert len(events) == 1
    assert events[0].request_headers == {
        "Accept": "application/json",
    }
    assert events[0].response_headers == {
        "X-Trace-ID": "trace-123",
    }


def test_nginx_parser_preserves_session_id_hash(tmp_path):
    log_file = tmp_path / "nginx_session.jsonl"

    session_hash = "sha256:" + "a" * 64

    log_file.write_text(
        '{"time":"2026-10-23T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"upstream_addr":"10.0.1.15:8080",'
        f'"session_id_hash":"{session_hash}"'
        '}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(str(log_file))

    assert len(events) == 1
    assert events[0].source == "nginx"
    assert events[0].backend == "10.0.1.15:8080"
    assert events[0].metadata["session_id_hash"] == session_hash


def _write_nginx_log_with_array(tmp_path):
    log_file = tmp_path / "nginx_mixed.jsonl"

    log_file.write_text(
        "\n".join([
            '{"time":"2026-10-21T10:00:00Z",'
            '"remote_addr":"192.0.2.10",'
            '"request_method":"GET",'
            '"request_uri":"/first",'
            '"status":200}',

            '["unexpected", "root"]',

            '{"time":"2026-10-21T10:00:02Z",'
            '"remote_addr":"192.0.2.20",'
            '"request_method":"GET",'
            '"request_uri":"/second",'
            '"status":200}',
        ]) + "\n",
        encoding="utf-8",
    )

    return log_file


def test_nginx_parser_continues_after_json_array(
    tmp_path,
):
    log_file = _write_nginx_log_with_array(tmp_path)

    events = parse_nginx_json_log(str(log_file))

    assert len(events) == 2
    assert [event.path for event in events] == [
        "/first",
        "/second",
    ]

    assert all(
        event.source == "nginx"
        for event in events
    )


def test_nginx_parser_records_invalid_root_type(
    tmp_path,
):
    log_file = _write_nginx_log_with_array(tmp_path)

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_root_type"
    )

    assert diagnostics.issues_dropped == 0

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


def test_nginx_parser_records_malformed_json_and_continues(
    tmp_path,
):
    log_file = tmp_path / "nginx_malformed.jsonl"

    log_file.write_text(
        "\n".join([
            '{"time":"2026-10-21T10:00:00Z",'
            '"remote_addr":"192.0.2.10",'
            '"request_method":"GET",'
            '"request_uri":"/first",'
            '"status":200}',

            "",

            '{"time":"2026-10-21T10:00:01Z",',

            '{"time":"2026-10-21T10:00:02Z",'
            '"remote_addr":"192.0.2.20",'
            '"request_method":"GET",'
            '"request_uri":"/second",'
            '"status":200}',
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.path for event in events] == [
        "/first",
        "/second",
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 3
    assert diagnostics.issues[0].reason == "invalid_json"

    assert diagnostics.issues_dropped == 0
    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


@pytest.mark.parametrize(
    "field_name,invalid_value",
    [
        ("http_x_forwarded_for", ["192.0.2.50"]),
        ("http_upgrade", 123),
    ],
)
def test_nginx_parser_rejects_invalid_field_types(
    tmp_path,
    field_name,
    invalid_value,
):
    log_file = tmp_path / "nginx_invalid_types.jsonl"

    valid_record = {
        "time": "2026-10-21T10:00:00Z",
        "remote_addr": "192.0.2.10",
        "request_method": "GET",
        "request_uri": "/first",
        "status": 200,
    }

    invalid_record = {
        **valid_record,
        "request_uri": "/invalid",
        field_name: invalid_value,
    }

    last_record = {
        **valid_record,
        "request_uri": "/last",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            json.dumps(invalid_record),
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_field_type"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


@pytest.mark.parametrize(
    "field_name,invalid_value",
    [
        ("request_uri", ["/admin"]),
        ("request_method", 123),
        ("remote_addr", {"ip": "192.0.2.99"}),
    ],
)
def test_nginx_parser_rejects_invalid_core_field_types(
    tmp_path,
    field_name,
    invalid_value,
):
    log_file = tmp_path / "nginx_invalid_core_fields.jsonl"

    valid_record = {
        "time": "2026-10-21T10:00:00Z",
        "remote_addr": "192.0.2.10",
        "request_method": "GET",
        "request_uri": "/first",
        "status": 200,
    }

    invalid_record = {
        **valid_record,
        "request_uri": "/invalid",
        field_name: invalid_value,
    }

    last_record = {
        **valid_record,
        "request_uri": "/last",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            json.dumps(invalid_record),
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_field_type"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


@pytest.mark.parametrize(
    "invalid_status",
    [
        "not-a-status",
        None,
        True,
        ["200"],
    ],
)
def test_nginx_parser_rejects_invalid_http_status(
    tmp_path,
    invalid_status,
):
    log_file = tmp_path / "nginx_invalid_status.jsonl"

    valid_record = {
        "time": "2026-10-21T10:00:00Z",
        "remote_addr": "192.0.2.10",
        "request_method": "GET",
        "request_uri": "/first",
        "status": 200,
    }

    invalid_record = {
        **valid_record,
        "request_uri": "/invalid",
        "status": invalid_status,
    }

    last_record = {
        **valid_record,
        "request_uri": "/last",
        "status": "201",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            json.dumps(invalid_record),
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [event.status_code for event in events] == [
        200,
        201,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == "invalid_status"

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


@pytest.mark.parametrize(
    "invalid_port",
    [
        "not-a-port",
        None,
        True,
        -1,
        65536,
        ["443"],
    ],
)
def test_nginx_parser_rejects_invalid_server_port(
    tmp_path,
    invalid_port,
):
    log_file = tmp_path / "nginx_invalid_server_port.jsonl"

    valid_record = {
        "time": "2026-10-21T10:00:00Z",
        "remote_addr": "192.0.2.10",
        "request_method": "GET",
        "request_uri": "/first",
        "status": 200,
        "server_port": 443,
    }

    invalid_record = {
        **valid_record,
        "request_uri": "/invalid",
        "server_port": invalid_port,
    }

    last_record = {
        **valid_record,
        "request_uri": "/last",
        "server_port": "8443",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            json.dumps(invalid_record),
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2

    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [event.server_port for event in events] == [
        443,
        8443,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_server_port"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


@pytest.mark.parametrize(
    "invalid_size",
    [
        "not-a-number",
        None,
        True,
        -1,
        12.5,
        ["2048"],
    ],
)
def test_nginx_parser_rejects_invalid_response_size(
    tmp_path,
    invalid_size,
):
    log_file = tmp_path / "nginx_invalid_response_size.jsonl"

    valid_record = {
        "time": "2026-10-21T10:00:00Z",
        "remote_addr": "192.0.2.10",
        "request_method": "GET",
        "request_uri": "/first",
        "status": 200,
        "bytes_sent": 2048,
    }

    invalid_record = {
        **valid_record,
        "request_uri": "/invalid",
        "bytes_sent": invalid_size,
    }

    last_record = {
        **valid_record,
        "request_uri": "/last",
        "bytes_sent": "4096",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            json.dumps(invalid_record),
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [event.response_size for event in events] == [
        2048,
        4096,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_response_size"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


@pytest.mark.parametrize(
    "invalid_time",
    [
        "bad-time",
        None,
        True,
        -0.25,
        "NaN",
        "Infinity",
        float("nan"),
        float("inf"),
        ["0.25"],
    ],
)
def test_nginx_parser_rejects_invalid_request_time(
    tmp_path,
    invalid_time,
):
    log_file = tmp_path / "nginx_invalid_request_time.jsonl"

    valid_record = {
        "time": "2026-10-21T10:00:00Z",
        "remote_addr": "192.0.2.10",
        "request_method": "GET",
        "request_uri": "/first",
        "status": 200,
        "request_time": 0.125,
    }

    invalid_record = {
        **valid_record,
        "request_uri": "/invalid",
        "request_time": invalid_time,
    }

    last_record = {
        **valid_record,
        "request_uri": "/last",
        "request_time": "0.5",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            json.dumps(invalid_record),
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [event.response_time_ms for event in events] == [
        125.0,
        500.0,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_request_time"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


def test_nginx_parser_preserves_missing_request_time(
    tmp_path,
):
    log_file = tmp_path / "nginx_missing_request_time.jsonl"

    log_file.write_text(
        json.dumps({
            "time": "2026-10-21T10:00:00Z",
            "remote_addr": "192.0.2.10",
            "request_method": "GET",
            "request_uri": "/health",
            "status": 200,
        }) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 1
    assert events[0].response_time_ms is None

    assert diagnostics.read == 1
    assert diagnostics.accepted == 1
    assert diagnostics.rejected == 0
    assert diagnostics.issues == []


@pytest.mark.parametrize(
    "invalid_upstream_status",
    [
        "not-a-status",
        True,
        ["502"],
        {"status": 502},
    ],
)
def test_nginx_parser_rejects_invalid_upstream_status(
    tmp_path,
    invalid_upstream_status,
):
    log_file = tmp_path / "nginx_invalid_upstream.jsonl"

    valid_record = {
        "time": "2026-10-21T10:00:00Z",
        "remote_addr": "192.0.2.10",
        "request_method": "GET",
        "request_uri": "/first",
        "status": 502,
        "upstream_status": 502,
    }

    invalid_record = {
        **valid_record,
        "request_uri": "/invalid",
        "upstream_status": invalid_upstream_status,
    }

    last_record = {
        **valid_record,
        "request_uri": "/last",
        "upstream_status": "503",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            json.dumps(invalid_record),
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2
    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [
        event.upstream_status for event in events
    ] == [502, 503]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_upstream_status"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


def test_nginx_parser_redacts_secrets_in_raw_event(
    tmp_path,
):
    log_file = tmp_path / "nginx_sensitive_raw.jsonl"

    record = {
        "time": "2026-10-21T10:00:00Z",
        "remote_addr": "192.0.2.10",
        "request_method": "GET",
        "request_uri": "/profile",
        "status": 200,
        "request_headers": {
            "Authorization": "Bearer secret-token-123",
            "Cookie": "session=secret-cookie-456",
            "X-API-Key": "secret-api-key-789",
        },
        "response_headers": {
            "Set-Cookie": "session=secret-response-999",
            "Cache-Control": "no-store",
        },
    }

    log_file.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    events = parse_nginx_json_log(str(log_file))

    assert len(events) == 1

    event = events[0]

    assert event.request_headers["Authorization"] == (
        "[REDACTED]"
    )
    assert event.response_headers["Set-Cookie"] == (
        "[REDACTED]"
    )

    secrets = (
        "secret-token-123",
        "secret-cookie-456",
        "secret-api-key-789",
        "secret-response-999",
    )

    for secret in secrets:
        assert secret not in event.raw_event
        assert secret not in event.to_dict()["raw_event"]

    sanitized = json.loads(event.raw_event)

    assert sanitized["request_headers"]["Authorization"] == (
        "[REDACTED]"
    )
    assert sanitized["response_headers"]["Set-Cookie"] == (
        "[REDACTED]"
    )

    assert sanitized["response_headers"]["Cache-Control"] == (
        "no-store"
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "time",
        "server_protocol",
        "host",
        "server_name",
        "server_addr",
        "request_id",
        "trace_id",
        "upstream",
        "upstream_addr",
        "http_user_agent",
        "http_referer",
        "ssl_protocol",
        "ssl_server_name",
        "session_id_hash",
    ],
)
def test_nginx_parser_rejects_invalid_optional_string_fields(
    tmp_path,
    field_name,
):
    log_file = tmp_path / "nginx_invalid_optional_fields.jsonl"

    valid_record = {
        "time": "2026-10-21T10:00:00Z",
        "remote_addr": "192.0.2.10",
        "request_method": "GET",
        "request_uri": "/first",
        "status": 200,
    }

    invalid_record = {
        **valid_record,
        "request_uri": "/invalid",
        field_name: ["unexpected", "type"],
    }

    last_record = {
        **valid_record,
        "request_uri": "/last",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            json.dumps(invalid_record),
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2

    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_field_type"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


def test_nginx_parser_rejects_multiple_upstream_statuses(
    tmp_path,
):
    log_file = tmp_path / "nginx_multiple_upstream.jsonl"

    base = {
        "time": "2026-10-21T10:00:00Z",
        "remote_addr": "192.0.2.10",
        "request_method": "GET",
        "status": 502,
    }

    records = [
        {
            **base,
            "request_uri": "/first",
            "upstream_status": 502,
        },
        {
            **base,
            "request_uri": "/unsupported",
            "upstream_status": "502, 503",
        },
        {
            **base,
            "request_uri": "/last",
            "upstream_status": "503",
        },
    ]

    log_file.write_text(
        "\n".join(json.dumps(record) for record in records)
        + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    events = parse_nginx_json_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [event.upstream_status for event in events] == [
        502,
        503,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_upstream_status"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )

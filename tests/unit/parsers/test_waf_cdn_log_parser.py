import json
import pytest

from src.parsers.parser_diagnostics import ParserDiagnostics
from src.parsers.waf_cdn_log_parser import (
    parse_waf_cdn_log,
)


def test_parse_waf_cdn_log_returns_valid_events():
    events = parse_waf_cdn_log(
        "data/raw/web/waf_cdn_events.jsonl"
    )

    assert len(events) == 3


def test_waf_event_contains_normalized_security_metadata():
    event = parse_waf_cdn_log(
        "data/raw/web/waf_cdn_events.jsonl"
    )[0]

    assert event.source == "waf_cdn"
    assert event.request_id == "waf-req-001"
    assert event.trace_id == "waf-trace-001"
    assert event.tls_version == "TLSv1.3"
    assert event.sni == "api.example.com"
    assert event.metadata["provider"] == "cloudflare"
    assert event.metadata["waf_action"] == "block"
    assert event.metadata["waf_rule_id"] == "100173"
    assert event.metadata["waf_rule_category"] == "sqli"


def test_waf_parser_does_not_store_raw_log_line():
    event = parse_waf_cdn_log(
        "data/raw/web/waf_cdn_events.jsonl"
    )[0]

    assert event.raw_event == ""

def test_waf_cdn_parser_preserves_request_and_response_headers(tmp_path):
    log_file = tmp_path / "waf_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/news",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"request_headers":{"X-Original-URL":"/admin"},'
        '"response_headers":{"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)

    assert len(events) == 1
    assert events[0].request_headers == {
        "X-Original-URL": "/admin",
    }
    assert events[0].response_headers == {
        "Cache-Control": "public, max-age=300",
    }

def test_waf_cdn_parser_redacts_sensitive_headers(tmp_path):
    log_file = tmp_path / "waf_sensitive_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/account",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"Authorization":"Bearer secret-token-123",'
        '"Cookie":"session=secret-session-456"},'
        '"response_headers":{'
        '"Set-Cookie":"session=secret-response-789"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)

    assert len(events) == 1

    event = events[0]

    assert "secret-token-123" not in event.request_headers["Authorization"]
    assert "secret-session-456" not in event.request_headers["Cookie"]
    assert "secret-response-789" not in event.response_headers["Set-Cookie"]

def test_waf_cdn_parser_ignores_invalid_header_fields(tmp_path):
    log_file = tmp_path / "waf_invalid_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/health",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"request_headers":["invalid", "headers"],'
        '"response_headers":null}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)

    assert len(events) == 1
    assert events[0].request_headers == {}
    assert events[0].response_headers == {}

def test_waf_cdn_parser_filters_invalid_header_values(tmp_path):
    log_file = tmp_path / "waf_invalid_header_values.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/health",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"Accept":"application/json",'
        '"Content-Length":123,'
        '"X-Test":["invalid"]},'
        '"response_headers":{'
        '"Cache-Control":"no-store",'
        '"Server":null}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)

    assert len(events) == 1

    assert events[0].request_headers == {
        "Accept": "application/json",
    }

    assert events[0].response_headers == {
        "Cache-Control": "no-store",
    }


def test_waf_parser_continues_after_json_null(tmp_path):
    log_file = tmp_path / "waf_null.jsonl"

    valid_record = {
        "timestamp": "2026-10-21T10:00:00Z",
        "client_ip": "192.0.2.10",
        "method": "GET",
        "path": "/first",
        "status_code": 200,
        "host": "api.example.com",
        "provider": "cloudflare",
        "action": "allow",
    }

    last_record = {
        **valid_record,
        "path": "/last",
        "status_code": 403,
        "action": "block",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            "null",
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(str(log_file))

    assert len(events) == 2

    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [event.status_code for event in events] == [
        200,
        403,
    ]

    assert [event.metadata["waf_action"] for event in events] == [
        "allow",
        "block",
    ]

    assert all(event.source == "waf_cdn" for event in events)


def test_waf_parser_records_invalid_json_and_root_types(
    tmp_path,
):
    log_file = tmp_path / "waf_diagnostics.jsonl"

    valid_record = {
        "timestamp": "2026-10-21T10:00:00Z",
        "client_ip": "192.0.2.10",
        "method": "GET",
        "path": "/first",
        "status_code": 200,
        "host": "api.example.com",
        "action": "allow",
    }

    last_record = {
        **valid_record,
        "path": "/last",
        "status_code": 403,
        "action": "block",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            "",
            "null",
            '{"timestamp":',
            "[]",
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="waf_cdn")

    events = parse_waf_cdn_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 2

    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [event.metadata["waf_action"] for event in events] == [
        "allow",
        "block",
    ]

    assert diagnostics.read == 5
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 3

    assert [
        (issue.line_number, issue.reason)
        for issue in diagnostics.issues
    ] == [
        (3, "invalid_root_type"),
        (4, "invalid_json"),
        (5, "invalid_root_type"),
    ]

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


@pytest.mark.parametrize(
    "invalid_status_code",
    [
        "not-a-status",
        None,
        True,
        -1,
        403.5,
        ["403"],
        {"code": 403},
    ],
)
def test_waf_parser_rejects_invalid_status_code(
    tmp_path,
    invalid_status_code,
):
    log_file = tmp_path / "waf_invalid_status.jsonl"

    valid_record = {
        "timestamp": "2026-10-21T10:00:00Z",
        "client_ip": "192.0.2.10",
        "method": "GET",
        "path": "/first",
        "status_code": 200,
        "host": "api.example.com",
        "action": "allow",
    }

    invalid_record = {
        **valid_record,
        "path": "/invalid",
        "status_code": invalid_status_code,
    }

    last_record = {
        **valid_record,
        "path": "/last",
        "status_code": "403",
        "action": "block",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            json.dumps(invalid_record),
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="waf_cdn")

    events = parse_waf_cdn_log(
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
        403,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert [
        (issue.line_number, issue.reason)
        for issue in diagnostics.issues
    ] == [
        (2, "invalid_status_code"),
    ]

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "timestamp",
        "client_ip",
        "method",
        "path",
        "protocol",
        "host",
        "request_id",
        "trace_id",
        "user_agent",
        "tls_version",
        "sni",
        "provider",
        "action",
        "rule_name",
        "rule_category",
    ],
)
def test_waf_parser_rejects_invalid_string_fields(
    tmp_path,
    field_name,
):
    log_file = tmp_path / "waf_invalid_string_fields.jsonl"

    valid_record = {
        "timestamp": "2026-10-21T10:00:00Z",
        "client_ip": "192.0.2.10",
        "method": "GET",
        "path": "/first",
        "status_code": 200,
        "host": "api.example.com",
        "provider": "cloudflare",
        "action": "allow",
    }

    invalid_record = {
        **valid_record,
        "path": "/invalid",
        field_name: ["unexpected", "type"],
    }

    last_record = {
        **valid_record,
        "path": "/last",
        "status_code": "403",
        "action": "block",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            json.dumps(invalid_record),
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="waf_cdn")

    events = parse_waf_cdn_log(
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
        403,
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert [
        (issue.line_number, issue.reason)
        for issue in diagnostics.issues
    ] == [
        (2, "invalid_field_type"),
    ]

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


def test_waf_parser_normalizes_rule_id_to_string(
    tmp_path,
):
    log_file = tmp_path / "waf_rule_id_types.jsonl"

    base = {
        "timestamp": "2026-10-21T10:00:00Z",
        "client_ip": "192.0.2.10",
        "method": "GET",
        "status_code": 200,
        "host": "api.example.com",
        "provider": "cloudflare",
        "action": "allow",
    }

    records = [
        {**base, "path": "/numeric", "rule_id": 100173},
        {
            **base,
            "path": "/text",
            "rule_id": "cf-managed-001",
        },
        {**base, "path": "/null", "rule_id": None},
        {**base, "path": "/missing"},
    ]

    log_file.write_text(
        "\n".join(json.dumps(record) for record in records)
        + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="waf_cdn")

    events = parse_waf_cdn_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert len(events) == 4

    assert [
        event.metadata["waf_rule_id"]
        for event in events
    ] == [
        "100173",
        "cf-managed-001",
        "",
        "",
    ]

    assert diagnostics.read == 4
    assert diagnostics.accepted == 4
    assert diagnostics.rejected == 0


@pytest.mark.parametrize(
    "invalid_rule_id",
    [
        True,
        -1,
        12.5,
        ["100173"],
        {"id": "100173"},
    ],
)
def test_waf_parser_rejects_invalid_rule_id(
    tmp_path,
    invalid_rule_id,
):
    log_file = tmp_path / "waf_invalid_rule_id.jsonl"

    base = {
        "timestamp": "2026-10-21T10:00:00Z",
        "client_ip": "192.0.2.10",
        "method": "GET",
        "status_code": 200,
        "host": "api.example.com",
        "provider": "cloudflare",
        "action": "block",
    }

    records = [
        {**base, "path": "/first", "rule_id": "100173"},
        {
            **base,
            "path": "/invalid",
            "rule_id": invalid_rule_id,
        },
        {**base, "path": "/last", "rule_id": "cf-102"},
    ]

    log_file.write_text(
        "\n".join(json.dumps(record) for record in records)
        + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="waf_cdn")

    events = parse_waf_cdn_log(
        str(log_file),
        diagnostics=diagnostics,
    )

    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert [
        event.metadata["waf_rule_id"]
        for event in events
    ] == [
        "100173",
        "cf-102",
    ]

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert [
        (issue.line_number, issue.reason)
        for issue in diagnostics.issues
    ] == [
        (2, "invalid_rule_id"),
    ]

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )

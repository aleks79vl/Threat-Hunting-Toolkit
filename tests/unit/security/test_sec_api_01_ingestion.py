import json

import pytest

from src.detection.web.load_balancer_rate_limit_detector import (
    detect_rate_limit_bypass,
)
from src.parsers.api_gateway_log_parser import (
    parse_api_gateway_log,
)


SYNTHETIC_A = "SEC_API_01_SYNTHETIC_A_NOT_REAL_71a9"
SYNTHETIC_B = "SEC_API_01_SYNTHETIC_B_NOT_REAL_82b7"
SYNTHETIC_C = "SEC_API_01_SYNTHETIC_C_NOT_REAL_93c6"


def _parse_events(tmp_path, identifiers):
    records = [
        {
            "timestamp": "2026-11-17T07:00:00Z",
            "client_ip": f"198.51.100.{index}",
            "http_method": "GET",
            "path": "/api/test",
            "status": 200,
            "api_key_id": identifier,
            "request_headers": {
                "X-API-Key": identifier,
            },
        }
        for index, identifier in enumerate(
            identifiers,
            start=1,
        )
    ]

    path = tmp_path / "api_gateway.jsonl"

    path.write_text(
        "\n".join(json.dumps(item) for item in records) + "\n",
        encoding="utf-8",
    )

    return parse_api_gateway_log(str(path))


def test_api_gateway_does_not_retain_raw_api_key_in_event(
    tmp_path,
):
    events = _parse_events(tmp_path, [SYNTHETIC_A])

    assert len(events) == 1

    event = events[0]

    assert (
        event.request_headers["X-API-Key"]
        == "[REDACTED]"
    )

    assert SYNTHETIC_A not in json.dumps(event.to_dict())
    assert SYNTHETIC_A not in repr(event)


def test_rate_limit_correlation_preserves_identity_without_secret(
    tmp_path,
):
    events = _parse_events(
        tmp_path,
        [
            SYNTHETIC_A,
            SYNTHETIC_A,
            SYNTHETIC_A,
            SYNTHETIC_B,
            SYNTHETIC_C,
        ],
    )

    assert len(events) == 5

    findings = detect_rate_limit_bypass(events)

    # Only identity A was observed from three distinct IPs.
    assert len(findings) == 1
    assert "3 distinct client IP" in findings[0].description

    serialized_events = json.dumps([
        event.to_dict()
        for event in events
    ])

    serialized_findings = json.dumps([
        finding.to_dict()
        for finding in findings
    ])

    for marker in (
        SYNTHETIC_A,
        SYNTHETIC_B,
        SYNTHETIC_C,
    ):
        assert marker not in serialized_events
        assert marker not in serialized_findings


def test_api_gateway_path_does_not_retain_query_credential(
    tmp_path,
):
    record = {
        "timestamp": "2026-11-17T07:00:00Z",
        "client_ip": "198.51.100.10",
        "http_method": "GET",
        "path": f"/api/test?api_key={SYNTHETIC_A}",
        "status": 200,
    }

    path = tmp_path / "api_gateway_path.jsonl"
    path.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(path))

    assert len(events) == 1
    assert SYNTHETIC_A not in events[0].path
    assert SYNTHETIC_A not in json.dumps(events[0].to_dict())


def test_api_gateway_user_agent_redacts_embedded_credential(
    tmp_path,
):
    record = {
        "timestamp": "2026-11-17T07:00:00Z",
        "client_ip": "198.51.100.10",
        "http_method": "GET",
        "path": "/api/test",
        "status": 200,
        "user_agent": f"TestClient api_key={SYNTHETIC_A}",
    }

    path = tmp_path / "api_gateway_user_agent.jsonl"
    path.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(path))

    assert len(events) == 1

    assert SYNTHETIC_A not in events[0].user_agent
    assert SYNTHETIC_A not in json.dumps(events[0].to_dict())


@pytest.mark.parametrize(
    "header_field",
    ["request_headers", "response_headers"],
)
def test_embedded_api_key_in_regular_header_is_redacted(
    tmp_path,
    header_field,
):
    record = {
        "timestamp": "2026-11-18T06:00:00Z",
        "client_ip": "198.51.100.10",
        "http_method": "GET",
        "path": "/api/test",
        "status": 200,
        header_field: {
            "X-Debug-Info": (
                f"trace api_key={SYNTHETIC_A}"
            ),
        },
    }

    path = tmp_path / "api_gateway_header.jsonl"
    path.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(path))

    assert len(events) == 1

    serialized = json.dumps(events[0].to_dict())

    assert SYNTHETIC_A not in serialized


def test_api_gateway_embedded_credential_in_metadata_is_masked(
    tmp_path,
):
    record = {
        "timestamp": "2026-11-18T06:00:00Z",
        "client_ip": "198.51.100.10",
        "http_method": "GET",
        "path": "/api/test",
        "status": 200,
        "principal_id": f"api_key={SYNTHETIC_A}",
    }

    path = tmp_path / "api_gateway_metadata.jsonl"
    path.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(path))

    assert len(events) == 1

    assert SYNTHETIC_A not in json.dumps(
        events[0].to_dict()
    )

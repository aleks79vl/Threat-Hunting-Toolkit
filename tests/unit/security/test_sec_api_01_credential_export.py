import json

import pytest

from src.detection.web.load_balancer_rate_limit_detector import (
    detect_rate_limit_bypass,
)
from src.parsers.api_gateway_log_parser import parse_api_gateway_log
from src.security.redaction import redact_for_export
from src.security.redaction import redact_data


SYNTHETIC_SECRET = "SEC_API_01_SYNTHETIC_NOT_REAL_9f72"


@pytest.mark.parametrize(
    "payload",
    [
        {"metadata": {"api_key_id": SYNTHETIC_SECRET}},
        {
            "findings": [
                {"ioc_value": f"api_key:{SYNTHETIC_SECRET}"}
            ]
        },
    ],
    ids=["api_key_id_metadata", "api_key_identity_string"],
)
def test_export_does_not_disclose_api_key_marker(payload):
    exported = redact_for_export(payload)
    assert SYNTHETIC_SECRET not in json.dumps(exported)


def test_api_gateway_detection_does_not_export_secret(tmp_path):
    records = [
        {
            "timestamp": "2026-11-17T06:00:00Z",
            "client_ip": f"198.51.100.{number}",
            "http_method": "GET",
            "path": "/test",
            "status": 200,
            "api_key_id": SYNTHETIC_SECRET,
            "request_headers": {"X-API-Key": SYNTHETIC_SECRET},
        }
        for number in (1, 2, 3)
    ]

    path = tmp_path / "api_gateway.jsonl"
    path.write_text(
        "\n".join(json.dumps(item) for item in records) + "\n",
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(path))
    assert len(events) == 3

    assert all(
        event.request_headers["X-API-Key"] == "[REDACTED]"
        for event in events
    )

    findings = detect_rate_limit_bypass(events)
    assert len(findings) == 1

    exported = redact_for_export({
        "findings": [finding.to_dict() for finding in findings]
    })

    assert SYNTHETIC_SECRET not in json.dumps(exported)


def test_redaction_preserves_non_sensitive_query_parameters():
    original_path = (
        f"/api/orders?api_key={SYNTHETIC_SECRET}"
        "&request_id=req-42&limit=10"
    )

    sanitized = redact_data({
        "path": original_path,
    })

    result = sanitized["path"]

    assert SYNTHETIC_SECRET not in result
    assert "api_key=[REDACTED]" in result

    assert "request_id=req-42" in result
    assert "limit=10" in result


def test_redaction_masks_url_encoded_api_key_name():
    original_path = (
        f"/api/orders?api%5Fkey={SYNTHETIC_SECRET}"
        "&request_id=req-42"
    )

    sanitized = redact_data({
        "path": original_path,
    })

    result = sanitized["path"]

    assert SYNTHETIC_SECRET not in result
    assert "request_id=req-42" in result


@pytest.mark.parametrize(
    "parameter",
    [
        "api_key",
        "api%5Fkey",
        "api_key%3D",
        "api%5Fkey%3D",
    ],
)
def test_redaction_encoded_parameter_boundaries(parameter):
    separator = "" if parameter.endswith("%3D") else "="

    original = (
        f"/api/orders?{parameter}{separator}{SYNTHETIC_SECRET}"
        "&request_id=req-42"
    )

    result = redact_data({"path": original})["path"]

    assert SYNTHETIC_SECRET not in result
    assert "request_id=req-42" in result

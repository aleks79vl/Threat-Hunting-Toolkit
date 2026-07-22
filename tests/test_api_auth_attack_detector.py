from src.detection.web.api_auth_attack_detector import (
    detect_api_auth_attacks,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_auth_event(
    *,
    client_ip: str,
    principal_id: str,
    auth_status: str = "failure",
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-19T10:00:00Z",
        source="api_gateway",
        client_ip=client_ip,
        method="POST",
        path="/v1/auth/login",
        status_code=401,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        metadata={
            "auth_status": auth_status,
            "principal_id": principal_id,
        },
    )


def test_detects_brute_force_against_one_account():
    events = [
        make_auth_event(
            client_ip="203.0.113.44",
            principal_id="account-1001",
        )
        for _ in range(3)
    ]

    findings = detect_api_auth_attacks(
        events,
        minimum_failures=3,
    )

    assert len(findings) == 1
    assert findings[0].title == "Potential API Brute Force Attack"


def test_detects_credential_stuffing_against_many_accounts():
    events = [
        make_auth_event(
            client_ip="203.0.113.44",
            principal_id="account-1001",
        ),
        make_auth_event(
            client_ip="203.0.113.44",
            principal_id="account-1002",
        ),
        make_auth_event(
            client_ip="203.0.113.44",
            principal_id="account-1003",
        ),
    ]

    findings = detect_api_auth_attacks(
        events,
        minimum_failures=5,
        minimum_accounts=3,
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Potential API Credential Stuffing Attack"
    )


def test_ignores_successful_authentication_events():
    findings = detect_api_auth_attacks(
        [
            make_auth_event(
                client_ip="203.0.113.44",
                principal_id="account-1001",
                auth_status="success",
            )
            for _ in range(5)
        ],
        minimum_failures=3,
    )

    assert findings == []
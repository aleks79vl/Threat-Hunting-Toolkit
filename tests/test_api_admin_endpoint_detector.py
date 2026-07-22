from src.detection.web.api_admin_endpoint_detector import (
    detect_api_admin_endpoint_access,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    path: str,
    status_code: int,
    principal_id: str,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-20T12:00:00Z",
        source="api_gateway",
        client_ip="203.0.113.44",
        method="GET",
        path=path,
        status_code=status_code,
        host="api.example.com",
        virtual_host="api.example.com",
        server_port=443,
        metadata={
            "principal_id": principal_id,
        },
    )


def test_detects_denied_admin_endpoint_access():
    findings = detect_api_admin_endpoint_access(
        [
            make_event(
                path="/v1/admin/users",
                status_code=403,
                principal_id="account-1001",
            )
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Unauthorized API Admin Endpoint Access"
    )
    assert findings[0].severity == "medium"


def test_detects_unexpected_successful_admin_access():
    findings = detect_api_admin_endpoint_access(
        [
            make_event(
                path="/internal/config",
                status_code=200,
                principal_id="account-1001",
            )
        ],
        authorized_admin_principals={"admin-1001"},
    )

    assert len(findings) == 1
    assert (
        findings[0].title
        == "Unexpected Successful API Admin Access"
    )
    assert findings[0].severity == "high"


def test_ignores_authorized_admin_access():
    findings = detect_api_admin_endpoint_access(
        [
            make_event(
                path="/management/health",
                status_code=200,
                principal_id="admin-1001",
            )
        ],
        authorized_admin_principals={"admin-1001"},
    )

    assert findings == []


def test_ignores_regular_api_endpoint():
    findings = detect_api_admin_endpoint_access(
        [
            make_event(
                path="/v1/profile",
                status_code=403,
                principal_id="account-1001",
            )
        ]
    )

    assert findings == []
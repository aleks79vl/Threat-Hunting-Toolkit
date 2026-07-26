from src.detection.web.waf_security_detector import (
    detect_waf_security_events,
)
from src.models.web_infrastructure_event import WebInfrastructureEvent


def make_event(
    *,
    client_ip: str,
    waf_action: str,
    rule_id: str,
) -> WebInfrastructureEvent:
    return WebInfrastructureEvent(
        timestamp="2026-07-22T10:00:00Z",
        source="waf_cdn",
        client_ip=client_ip,
        method="GET",
        path="/v1/products",
        status_code=403,
        host="api.example.com",
        virtual_host="api.example.com",
        metadata={
            "waf_action": waf_action,
            "waf_rule_id": rule_id,
        },
    )


def test_detects_repeated_waf_blocks():
    findings = detect_waf_security_events(
        [
            make_event(
                client_ip="203.0.113.44",
                waf_action="block",
                rule_id="100173",
            )
            for _ in range(3)
        ]
    )

    assert len(findings) == 1
    assert findings[0].title == "Repeated WAF Blocks Detected"


def test_detects_multiple_waf_rules_from_one_ip():
    findings = detect_waf_security_events(
        [
            make_event(
                client_ip="203.0.113.44",
                waf_action="block",
                rule_id="100173",
            ),
            make_event(
                client_ip="203.0.113.44",
                waf_action="block",
                rule_id="100174",
            ),
        ],
        minimum_blocks=3,
        minimum_distinct_rules=2,
    )

    assert len(findings) == 1
    assert findings[0].title == "Multiple WAF Rules Triggered"


def test_ignores_allowed_waf_events():
    findings = detect_waf_security_events(
        [
            make_event(
                client_ip="203.0.113.44",
                waf_action="allow",
                rule_id="100173",
            )
            for _ in range(3)
        ]
    )

    assert findings == []
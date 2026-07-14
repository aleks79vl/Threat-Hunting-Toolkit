from src.parsers.web_log_parser import parse_web_log
from src.detection.web.web_attack_detector import detect_web_attacks


def test_detect_web_attacks_returns_findings():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert len(findings) >= 7


def test_detect_sql_injection():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "SQL Injection Attempt Detected"
        for finding in findings
    )


def test_detect_xss():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "XSS Attempt Detected"
        for finding in findings
    )


def test_detect_directory_traversal():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "Directory Traversal Attempt Detected"
        for finding in findings
    )


def test_detect_suspicious_user_agent():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "Suspicious Web User-Agent Detected"
        for finding in findings
    )


def test_detect_admin_brute_force():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "Possible Admin Brute Force Detected"
        for finding in findings
    )


def test_detect_web_enumeration():
    events = parse_web_log(
        "data/raw/web/apache_access.log"
    )

    findings = detect_web_attacks(events)

    assert any(
        finding.title == "Possible Web Enumeration Detected"
        for finding in findings
    )
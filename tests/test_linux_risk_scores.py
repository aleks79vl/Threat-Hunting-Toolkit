from src.correlation.risk_scoring import calculate_risk_score
from src.models.threat_finding import ThreatFinding


RISK_CONFIG = "config/risk_scores.json"


def create_finding(title: str) -> ThreatFinding:
    return ThreatFinding(
        title=title,
        severity="medium",
        description="test",
        source="Linux Log Detection",
        recommendation="Investigate",
    )


def test_failed_ssh_login_risk_score():
    finding = calculate_risk_score(
        create_finding("Failed SSH Login Detected"),
        RISK_CONFIG,
    )

    assert finding.risk_score == 40


def test_ssh_bruteforce_risk_score():
    finding = calculate_risk_score(
        create_finding("SSH Brute Force Detected"),
        RISK_CONFIG,
    )

    assert finding.risk_score == 85


def test_successful_login_after_failures_risk_score():
    finding = calculate_risk_score(
        create_finding(
            "Successful Login After Failures Detected"
        ),
        RISK_CONFIG,
    )

    assert finding.risk_score == 90


def test_telnet_activity_risk_score():
    finding = calculate_risk_score(
        create_finding("Telnet Activity Detected"),
        RISK_CONFIG,
    )

    assert finding.risk_score == 50


def test_repeated_telnet_attempts_risk_score():
    finding = calculate_risk_score(
        create_finding(
            "Repeated Telnet Login Attempts Detected"
        ),
        RISK_CONFIG,
    )

    assert finding.risk_score == 75


def test_sudo_abuse_risk_score():
    finding = calculate_risk_score(
        create_finding("Sudo Abuse Detected"),
        RISK_CONFIG,
    )

    assert finding.risk_score == 80


def test_new_linux_user_risk_score():
    finding = calculate_risk_score(
        create_finding("New Linux User Detected"),
        RISK_CONFIG,
    )

    assert finding.risk_score == 60


def test_privileged_user_modification_risk_score():
    finding = calculate_risk_score(
        create_finding(
            "Privileged User Modification Detected"
        ),
        RISK_CONFIG,
    )

    assert finding.risk_score == 90


def test_suspicious_cron_activity_risk_score():
    finding = calculate_risk_score(
        create_finding("Suspicious Cron Activity Detected"),
        RISK_CONFIG,
    )

    assert finding.risk_score == 85


def test_linux_service_manipulation_risk_score():
    finding = calculate_risk_score(
        create_finding(
            "Linux Service Manipulation Detected"
        ),
        RISK_CONFIG,
    )

    assert finding.risk_score == 70


def test_repeated_linux_service_manipulation_risk_score():
    finding = calculate_risk_score(
        create_finding(
            "Repeated Linux Service Manipulation Detected"
        ),
        RISK_CONFIG,
    )

    assert finding.risk_score == 85
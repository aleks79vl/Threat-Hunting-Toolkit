from src.detection.linux_audit_tampering_detector import (detect_linux_audit_tampering,)
from src.detection.linux_detection_context import LinuxDetectionContext
from src.models.linux_process_execution import LinuxProcessExecution


class FakeLinuxEvent:
    def __init__(
        self,
        command="",
        process="",
        user="root",
        source_ip="",
        hostname="ubuntu-server",
        timestamp="Jul 7 10:00:01",
        message="",
        raw_log="",
    ):
        self.command = command
        self.process = process
        self.user = user
        self.source_ip = source_ip
        self.hostname = hostname
        self.timestamp = timestamp
        self.message = message
        self.raw_log = raw_log


def create_execution(
    command: str = "",
    process: str = "",
    user: str = "root",
    source_ip: str = "",
    message: str = "",
) -> LinuxProcessExecution:
    event = FakeLinuxEvent(
        command=command,
        process=process,
        user=user,
        source_ip=source_ip,
        message=message,
    )

    context = LinuxDetectionContext.from_event(event)

    return LinuxProcessExecution.from_context(context)


def test_detect_auditd_service_stop():
    executions = [create_execution(command="systemctl stop auditd")]

    findings = detect_linux_audit_tampering(executions)

    assert len(findings) == 1
    assert findings[0].title == "Linux Audit Tampering Activity Detected"
    assert findings[0].severity == "critical"
    assert findings[0].source == "Linux Host Detection"


def test_detect_auditd_service_disable():
    executions = [create_execution(command="systemctl disable auditd")]

    findings = detect_linux_audit_tampering(executions)

    assert len(findings) == 1


def test_detect_service_auditd_stop():
    executions = [create_execution(command="service auditd stop")]

    findings = detect_linux_audit_tampering(executions)

    assert len(findings) == 1


def test_detect_auditctl_disable():
    executions = [create_execution(command="auditctl -e 0")]

    findings = detect_linux_audit_tampering(executions)

    assert len(findings) == 1


def test_detect_audit_rules_removal():
    executions = [create_execution(command="rm -f /etc/audit/audit.rules")]

    findings = detect_linux_audit_tampering(executions)

    assert len(findings) == 1


def test_detect_audit_rules_directory_activity():
    executions = [create_execution(command="rm /etc/audit/rules.d/security.rules")]

    findings = detect_linux_audit_tampering(executions)

    assert len(findings) == 1


def test_ignore_auditd_status_check():
    executions = [create_execution(command="systemctl status auditd")]

    findings = detect_linux_audit_tampering(executions)

    assert findings == []


def test_ignore_audit_rule_listing():
    executions = [create_execution(command="auditctl -l")]

    findings = detect_linux_audit_tampering(executions)

    assert findings == []


def test_ignore_empty_executions():
    findings = detect_linux_audit_tampering([])

    assert findings == []
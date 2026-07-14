from src.detection.linux.detection_context import LinuxDetectionContext
from src.detection.linux.file_permission_detector import (detect_suspicious_file_permissions,)
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


def test_detect_chmod_777():
    executions = [create_execution(command="chmod 777 /tmp/payload.sh")]

    findings = detect_suspicious_file_permissions(executions)

    assert len(findings) == 1
    assert findings[0].title == ("Suspicious Linux File Permission Change Detected")
    assert findings[0].severity == "high"
    assert findings[0].source == "Linux Host Detection"


def test_detect_recursive_chmod_777():
    executions = [create_execution(command="chmod -R 777 /var/tmp/payload")]

    findings = detect_suspicious_file_permissions(executions)

    assert len(findings) == 1


def test_detect_suid_permission():
    executions = [create_execution(command="chmod u+s /tmp/payload")]

    findings = detect_suspicious_file_permissions(executions)

    assert len(findings) == 1


def test_detect_numeric_suid_permission():
    executions = [create_execution(command="chmod 4755 /tmp/payload")]

    findings = detect_suspicious_file_permissions(executions)

    assert len(findings) == 1


def test_detect_sgid_permission():
    executions = [create_execution(command="chmod g+s /tmp/payload")]

    findings = detect_suspicious_file_permissions(executions)

    assert len(findings) == 1


def test_detect_root_ownership_on_usr_bin():
    executions = [create_execution(command="chown root:root /usr/bin/payload")]

    findings = detect_suspicious_file_permissions(executions)

    assert len(findings) == 1


def test_detect_root_ownership_on_shadow():
    executions = [create_execution(command="chown root:root /etc/shadow")]

    findings = detect_suspicious_file_permissions(executions)

    assert len(findings) == 1


def test_ignore_normal_chmod():
    executions = [create_execution(command="chmod 644 /opt/application.conf")]

    findings = detect_suspicious_file_permissions(executions)

    assert findings == []


def test_ignore_normal_root_ownership():
    executions = [create_execution(command="chown root /opt/application.conf")]

    findings = detect_suspicious_file_permissions(executions)

    assert findings == []


def test_ignore_file_listing():
    executions = [create_execution(command="ls -la /usr/bin/")]

    findings = detect_suspicious_file_permissions(executions)

    assert findings == []


def test_ignore_empty_executions():
    findings = detect_suspicious_file_permissions([])

    assert findings == []
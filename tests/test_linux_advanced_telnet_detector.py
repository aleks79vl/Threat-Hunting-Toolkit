from src.detection.linux_advanced_telnet_detector import (
    detect_advanced_telnet_activity,
)
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
    source_ip: str = "",
    message: str = "",
) -> LinuxProcessExecution:
    event = FakeLinuxEvent(
        command=command,
        process=process,
        source_ip=source_ip,
        message=message,
    )

    context = LinuxDetectionContext.from_event(event)

    return LinuxProcessExecution.from_context(context)


def test_detect_telnet_client_execution():
    executions = [create_execution(command="telnet 10.0.0.5 23")]

    findings = detect_advanced_telnet_activity(executions)

    assert len(findings) == 1
    assert findings[0].title == "Advanced Telnet Activity Detected"
    assert findings[0].severity == "medium"
    assert findings[0].port == 23
    assert findings[0].source == "Linux Host Detection"


def test_detect_usr_bin_telnet_execution():
    executions = [create_execution(command="/usr/bin/telnet 10.0.0.5")]

    findings = detect_advanced_telnet_activity(executions)

    assert len(findings) == 1


def test_detect_telnet_daemon_process():
    executions = [create_execution(process="in.telnetd",source_ip="198.51.100.25",)]

    findings = detect_advanced_telnet_activity(executions)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].ip == "198.51.100.25"


def test_detect_telnet_service_activity():
    executions = [create_execution(message="Started telnet.service")]

    findings = detect_advanced_telnet_activity(executions)

    assert len(findings) == 1


def test_detect_telnet_socket_activity():
    executions = [create_execution(message="Started telnet.socket")]

    findings = detect_advanced_telnet_activity(executions)

    assert len(findings) == 1


def test_ignore_ssh_process():
    executions = [create_execution(command="ssh 10.0.0.5")]

    findings = detect_advanced_telnet_activity(executions)

    assert findings == []


def test_ignore_empty_executions():
    findings = detect_advanced_telnet_activity([])

    assert findings == []
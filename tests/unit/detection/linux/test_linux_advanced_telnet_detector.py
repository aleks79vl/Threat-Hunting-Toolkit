from src.detection.linux.advanced_telnet_detector import (
    detect_advanced_telnet_activity,
)
from src.detection.linux.detection_context import LinuxDetectionContext
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


def test_process_execution_preserves_normalized_utc():
    event = FakeLinuxEvent(
        command="telnet 10.0.0.5 23",
        timestamp="Jul 7 10:00:01",
    )
    event.timestamp_utc = (
        "2026-07-07T07:00:01.123456789+00:00"
    )

    context = LinuxDetectionContext.from_event(event)
    execution = LinuxProcessExecution.from_context(context)

    assert execution.timestamp == "Jul 7 10:00:01"
    assert execution.timestamp_utc == (
        "2026-07-07T07:00:01.123456789+00:00"
    )
    assert event.timestamp == "Jul 7 10:00:01"


def test_advanced_telnet_finding_preserves_normalized_utc():
    event = FakeLinuxEvent(
        command="/usr/bin/telnet 10.0.0.5",
        timestamp="Jul 7 10:00:01",
    )
    event.timestamp_utc = (
        "2026-07-07T07:00:01.123456789+00:00"
    )

    context = LinuxDetectionContext.from_event(event)
    execution = LinuxProcessExecution.from_context(context)

    findings = detect_advanced_telnet_activity(
        [execution]
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == (
        "Advanced Telnet Activity Detected"
    )
    assert finding.first_seen == (
        "2026-07-07T07:00:01.123456789+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T07:00:01.123456789+00:00"
    )


def test_advanced_telnet_finding_does_not_invent_unknown_time():
    execution = create_execution(
        command="telnet 10.0.0.5 23"
    )

    findings = detect_advanced_telnet_activity(
        [execution]
    )

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None

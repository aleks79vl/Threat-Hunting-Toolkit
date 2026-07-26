from src.detection.linux.detection_context import (LinuxDetectionContext,)
from src.models.linux_process_execution import (LinuxProcessExecution,)


class FakeLinuxEvent:
    def __init__(
        self,
        command=None,
        process=None,
        user=None,
        source_ip=None,
        hostname=None,
        timestamp=None,
        raw_message=None,
    ):
        self.command = command
        self.process = process
        self.user = user
        self.source_ip = source_ip
        self.hostname = hostname
        self.timestamp = timestamp
        self.raw_message = raw_message


def create_execution(
    command=None,
    process=None,
    user=None,
    source_ip=None,
    hostname=None,
    timestamp=None,
    raw_message=None,
):
    event = FakeLinuxEvent(
        command=command,
        process=process,
        user=user,
        source_ip=source_ip,
        hostname=hostname,
        timestamp=timestamp,
        raw_message=raw_message,
    )

    context = LinuxDetectionContext.from_event(event)

    return LinuxProcessExecution.from_context(context)


def test_linux_process_execution_from_context():
    execution = create_execution(
        command=" /BIN/BASH -I ",
        process=" BASH ",
        user=" ROOT ",
        source_ip=" 203.0.113.50 ",
        hostname=" UBUNTU-SERVER ",
        timestamp=" Jul 7 10:00:01 ",
    )

    assert execution.command == "/bin/bash -i"
    assert execution.executable == "/bin/bash"
    assert execution.process == "bash"
    assert execution.user == "root"
    assert execution.source_ip == "203.0.113.50"
    assert execution.hostname == "ubuntu-server"
    assert execution.timestamp == "jul 7 10:00:01"


def test_linux_process_execution_extracts_python_executable():
    execution = create_execution(
        command="python -c import socket",
    )

    assert execution.executable == "python"


def test_linux_process_execution_extracts_telnet_executable():
    execution = create_execution(
        command="telnet 10.0.0.5 23",
    )

    assert execution.executable == "telnet"


def test_linux_process_execution_handles_empty_command():
    execution = create_execution()

    assert execution.command == ""
    assert execution.executable == ""


def test_linux_process_execution_searchable_text():
    execution = create_execution(
        command="/bin/bash -i",
        process="bash",
        user="root",
        source_ip="203.0.113.50",
        hostname="ubuntu-server",
    )

    searchable_text = execution.searchable_text()

    assert "/bin/bash -i" in searchable_text
    assert "bash" in searchable_text
    assert "root" in searchable_text
    assert "203.0.113.50" in searchable_text
    assert "ubuntu-server" in searchable_text
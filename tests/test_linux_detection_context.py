from src.detection.linux_detection_context import (LinuxDetectionContext,)


class FakeLinuxEvent:
    def __init__(
        self,
        command=None,
        process=None,
        service=None,
        user=None,
        source_ip=None,
        raw_message=None,
    ):
        self.command = command
        self.process = process
        self.service = service
        self.user = user
        self.source_ip = source_ip
        self.raw_message = raw_message


def test_linux_detection_context_normalizes_values():
    event = FakeLinuxEvent(
        command="  /BIN/BASH -I  ",
        process=" BASH ",
        service=" SSHD ",
        user=" ROOT ",
        source_ip=" 203.0.113.50 ",
        raw_message=" Suspicious COMMAND Execution ",
    )

    context = LinuxDetectionContext.from_event(event)

    assert context.command == "/bin/bash -i"
    assert context.process == "bash"
    assert context.service == "sshd"
    assert context.user == "root"
    assert context.source_ip == "203.0.113.50"
    assert context.raw_message == "suspicious command execution"


def test_linux_detection_context_handles_none_values():
    event = FakeLinuxEvent()

    context = LinuxDetectionContext.from_event(event)

    assert context.command == ""
    assert context.process == ""
    assert context.service == ""
    assert context.user == ""
    assert context.source_ip == ""
    assert context.raw_message == ""


def test_linux_detection_context_combined_text():
    event = FakeLinuxEvent(
        command="/bin/bash -i",
        process="bash",
        user="root",
        source_ip="203.0.113.50",
    )

    context = LinuxDetectionContext.from_event(event)

    combined = context.combined_text()

    assert "/bin/bash -i" in combined
    assert "bash" in combined
    assert "root" in combined
    assert "203.0.113.50" in combined
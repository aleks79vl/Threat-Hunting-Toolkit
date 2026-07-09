from src.detection.linux_user_privilege_detector import (
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
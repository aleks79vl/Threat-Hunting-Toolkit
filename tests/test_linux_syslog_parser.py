from src.parsers.linux_syslog_parser import parse_syslog


FIXTURE = "tests/fixtures/linux/syslog_sample.log"


def test_parse_syslog_returns_events():
    events = parse_syslog(FIXTURE)

    assert len(events) == 5


def test_parse_cron_event():
    events = parse_syslog(FIXTURE)

    event = events[0]

    assert event.service == "cron"
    assert event.process == "CRON"
    assert event.pid == "2301"
    assert event.action == "cron_execute"
    assert event.status == "success"


def test_parse_systemd_service_start():
    events = parse_syslog(FIXTURE)

    event = events[1]

    assert event.service == "systemd"
    assert event.process == "systemd"
    assert event.action == "service_start"
    assert event.status == "success"


def test_parse_systemd_service_stop():
    events = parse_syslog(FIXTURE)

    event = events[2]

    assert event.action == "service_stop"


def test_parse_systemd_service_restart():
    events = parse_syslog(FIXTURE)

    event = events[3]

    assert event.action == "service_restart"


def test_parse_user_creation_event():
    events = parse_syslog(FIXTURE)

    event = events[4]

    assert event.service == "user"
    assert event.process == "useradd"
    assert event.pid == "2401"
    assert event.user == "backup"
    assert event.action == "user_create"
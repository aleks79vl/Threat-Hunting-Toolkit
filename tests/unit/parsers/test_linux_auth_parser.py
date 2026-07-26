from src.parsers.linux_auth_parser import parse_auth_log


FIXTURE = "tests/fixtures/linux/auth_sample.log"


def test_parse_auth_log_returns_events():
    events = parse_auth_log(FIXTURE)

    assert len(events) == 4


def test_parse_failed_ssh_login():
    events = parse_auth_log(FIXTURE)

    event = events[0]

    assert event.service == "ssh"
    assert event.process == "sshd"
    assert event.pid == "1425"
    assert event.user == "admin"
    assert event.source_ip == "203.0.113.50"
    assert event.port == 49822
    assert event.action == "authentication"
    assert event.status == "failed"


def test_parse_successful_ssh_login():
    events = parse_auth_log(FIXTURE)

    event = events[1]

    assert event.service == "ssh"
    assert event.user == "alex"
    assert event.source_ip == "192.168.1.10"
    assert event.port == 51244
    assert event.action == "authentication"
    assert event.status == "success"


def test_parse_sudo_command():
    events = parse_auth_log(FIXTURE)

    event = events[2]

    assert event.service == "sudo"
    assert event.process == "sudo"
    assert event.user == "alex"
    assert event.action == "command"
    assert event.status == "success"


def test_parse_telnet_connection():
    events = parse_auth_log(FIXTURE)

    event = events[3]

    assert event.service == "telnet"
    assert event.process == "in.telnetd"
    assert event.pid == "2201"
    assert event.source_ip == "198.51.100.25"
    assert event.port == 23
    assert event.action == "connection"
    assert event.status == "success"
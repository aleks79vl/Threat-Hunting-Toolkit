from src.models.linux_event import LinuxEvent


def test_create_empty_linux_event():
    event = LinuxEvent()

    assert event.timestamp == ""
    assert event.hostname == ""
    assert event.service == ""
    assert event.process == ""
    assert event.pid == ""
    assert event.message == ""
    assert event.user == ""
    assert event.source_ip == ""
    assert event.port is None
    assert event.action == ""
    assert event.status == ""
    assert event.raw_log == ""


def test_create_linux_authentication_event():
    event = LinuxEvent(
        timestamp="Jul  7 08:15:01",
        hostname="ubuntu-server",
        service="ssh",
        process="sshd",
        pid="1425",
        message=(
            "Failed password for invalid user admin "
            "from 203.0.113.50 port 49822 ssh2"
        ),
        user="admin",
        source_ip="203.0.113.50",
        port=49822,
        action="authentication",
        status="failed",
        raw_log=(
            "Jul  7 08:15:01 ubuntu-server "
            "sshd[1425]: Failed password for invalid user admin "
            "from 203.0.113.50 port 49822 ssh2"
        ),
    )

    assert event.hostname == "ubuntu-server"
    assert event.service == "ssh"
    assert event.process == "sshd"
    assert event.pid == "1425"
    assert event.user == "admin"
    assert event.source_ip == "203.0.113.50"
    assert event.port == 49822
    assert event.action == "authentication"
    assert event.status == "failed"


def test_create_linux_telnet_event():
    event = LinuxEvent(
        timestamp="Jul  7 08:20:10",
        hostname="legacy-server",
        service="telnet",
        process="in.telnetd",
        pid="2201",
        message="Connection from 198.51.100.25",
        source_ip="198.51.100.25",
        port=23,
        action="connection",
        status="success",
    )

    assert event.service == "telnet"
    assert event.process == "in.telnetd"
    assert event.source_ip == "198.51.100.25"
    assert event.port == 23
    assert event.action == "connection"


def test_linux_event_port_can_be_none():
    event = LinuxEvent(
        service="systemd",
        process="systemd",
        message="Started OpenSSH server daemon",
    )

    assert event.port is None
from src.models.linux_event import LinuxEvent
from src.reporting.linux_statistics import generate_linux_statistics


def create_event(action="",status="",user="",source_ip="",):
    return LinuxEvent(timestamp="Jul 7 10:00:01",hostname="ubuntu",
        process="sshd",message="test event",user=user,
        source_ip=source_ip,port=None,action=action,status=status,
        raw_log="test log",)


def test_linux_statistics_total_events():
    events = [
        create_event(),
        create_event(),
        create_event(),
    ]

    statistics = generate_linux_statistics(events)

    assert statistics["total_events"] == 3


def test_linux_statistics_actions():
    events = [
        create_event(action="failed_login"),
        create_event(action="failed_login"),
        create_event(action="successful_login"),
    ]

    statistics = generate_linux_statistics(events)

    assert statistics["actions"]["failed_login"] == 2
    assert statistics["actions"]["successful_login"] == 1


def test_linux_statistics_statuses():
    events = [
        create_event(status="failure"),
        create_event(status="failure"),
        create_event(status="success"),
    ]

    statistics = generate_linux_statistics(events)

    assert statistics["statuses"]["failure"] == 2
    assert statistics["statuses"]["success"] == 1


def test_linux_statistics_users():
    events = [
        create_event(user="admin"),
        create_event(user="admin"),
        create_event(user="alex"),
    ]

    statistics = generate_linux_statistics(events)

    assert statistics["users"]["admin"] == 2
    assert statistics["users"]["alex"] == 1


def test_linux_statistics_source_ips():
    events = [
        create_event(source_ip="203.0.113.50"),
        create_event(source_ip="203.0.113.50"),
        create_event(source_ip="198.51.100.25"),
    ]

    statistics = generate_linux_statistics(events)

    assert statistics["source_ips"]["203.0.113.50"] == 2
    assert statistics["source_ips"]["198.51.100.25"] == 1


def test_linux_statistics_ignore_empty_values():
    events = [
        create_event(),
    ]

    statistics = generate_linux_statistics(events)

    assert statistics["actions"] == {}
    assert statistics["statuses"] == {}
    assert statistics["users"] == {}
    assert statistics["source_ips"] == {}
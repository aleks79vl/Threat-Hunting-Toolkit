from src.parsers.windows_event_parser import parse_windows_events


def test_parse_windows_events_returns_events():
    events = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )

    assert len(events) == 7


def test_successful_logon_event():
    event = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )[0]

    assert event.source == "Windows"
    assert event.event_type == "4624"
    assert event.username == "administrator"
    assert event.hostname == "WIN-DC01"
    assert event.src_ip == "192.168.1.10"
    assert event.raw_event == "Successful logon: winlogon.exe"


def test_failed_logon_event():
    event = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )[1]

    assert event.event_type == "4625"
    assert event.src_ip == "203.0.113.15"
    assert event.raw_event == "Failed logon: winlogon.exe"


def test_user_created_event():
    event = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )[3]

    assert event.event_type == "4720"
    assert event.username == "temp_admin"
    assert event.raw_event == "User account created: net.exe"


def test_admin_group_change_event():
    event = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )[4]

    assert event.event_type == "4732"
    assert event.username == "temp_admin"
    assert "Administrators" in event.raw_event


def test_powershell_process_event():
    event = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )[5]

    assert event.event_type == "4688"
    assert event.username == "administrator"
    assert event.raw_event == "Process created: powershell.exe"


def test_audit_log_cleared_event():
    event = parse_windows_events(
        "data/raw/windows/security_events.csv"
    )[6]

    assert event.event_type == "1102"
    assert event.raw_event == "Audit log cleared: wevtutil.exe"

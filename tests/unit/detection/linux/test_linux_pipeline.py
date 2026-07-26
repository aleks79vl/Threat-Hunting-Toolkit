from src.detection.linux.linux_pipeline import (
    run_linux_detection_pipeline,
)


def test_linux_pipeline_returns_empty_result_when_logs_are_missing(
    tmp_path,
):
    result = run_linux_detection_pipeline(
        linux_auth_file=str(tmp_path / "missing-auth.log"),
        linux_syslog_file=str(tmp_path / "missing-syslog.log"),
    )

    assert result.events == []
    assert result.findings == []
    assert result.statistics == {
        "linux_statistics": {
            "total_events": 0,
            "actions": {},
            "statuses": {},
            "users": {},
            "source_ips": {},
        },
        "linux_execution_statistics": {
            "total_executions": 0,
            "suspicious_executions": 0,
            "unique_executables": 0,
            "top_executables": [],
            "top_users": [],
            "mitre_statistics": [],
        },
    }

def test_linux_pipeline_parses_fixture_logs():
    result = run_linux_detection_pipeline(
        linux_auth_file="tests/fixtures/linux/auth_sample.log",
        linux_syslog_file="tests/fixtures/linux/syslog_sample.log",
    )

    assert result.events
    assert (
        result.statistics["linux_statistics"]["total_events"]
        == len(result.events)
    )
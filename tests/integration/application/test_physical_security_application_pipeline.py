from src.application.physical_security_application_pipeline import (
    run_physical_security_application_pipeline,
)
from src.config.app_config import default_app_config


def test_physical_security_application_pipeline_runs_default_source():
    config = default_app_config()

    result = run_physical_security_application_pipeline(
        physical_events_file=config.physical_events_file,
    )

    assert len(result.events) == 5
    assert len(result.policy_findings) == 4
    assert len(result.correlation_findings) == 6
    assert len(result.all_findings) == 23
    assert result.risk_score == 100
    assert result.statistics["events_parsed"] == 5
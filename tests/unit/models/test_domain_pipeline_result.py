from src.models.domain_pipeline_result import DomainPipelineResult


def test_domain_pipeline_result_exposes_events_findings_and_statistics():
    events = ["network-event"]
    findings = []
    statistics = {"total_events": 1}

    result = DomainPipelineResult(
        events=events,
        findings=findings,
        statistics=statistics,
    )

    assert result.events == events
    assert result.findings == findings
    assert result.statistics == statistics
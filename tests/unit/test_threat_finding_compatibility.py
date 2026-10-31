from src.models.threat_finding import ThreatFinding

from inspect import Parameter, signature


def test_threat_finding_preserves_legacy_positional_arguments():
    finding = ThreatFinding(
        "Test Finding",
        "high",
        "Test description",
        "Test source",
        "",
        "",
        0,
        "T1059",
        "Investigate activity",
        55,
        None,
        {},
        "Command and Scripting Interpreter",
        "Execution",
    )

    assert finding.technique == "T1059"
    assert finding.recommendation == "Investigate activity"
    assert finding.risk_score == 55
    assert finding.technique_name == (
        "Command and Scripting Interpreter"
    )
    assert finding.tactic == "Execution"


def test_new_risk_scoring_metadata_is_keyword_only():
    parameters = signature(ThreatFinding).parameters

    assert (
        parameters["ioc_match"].kind
        is Parameter.POSITIONAL_OR_KEYWORD
    )

    for field_name in (
        "risk_base_sources",
        "scoring_version",
        "scoring_policy_hash",
    ):
        assert (
            parameters[field_name].kind
            is Parameter.KEYWORD_ONLY
        )

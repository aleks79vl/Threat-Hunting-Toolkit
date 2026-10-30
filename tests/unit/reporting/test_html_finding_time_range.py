import pytest

from src.models.threat_finding import ThreatFinding
from src.models.threat_report import ThreatReport
from src.reporting.html_report_generator import generate_html_report


def _finding(
    *,
    title="Temporal Evidence Test",
    first_seen=None,
    last_seen=None,
):
    return ThreatFinding(
        title=title,
        severity="medium",
        description="Synthetic security event",
        source="Linux Log Detection",
        hostname="test-host",
        recommendation="Review the event.",
        first_seen=first_seen,
        last_seen=last_seen,
    )


def _render_detected_threats(tmp_path, findings):
    report = ThreatReport(
        title="Threat Hunting Report",
        generated_at="2026-07-07 15:00:00",
        findings=findings,
    )

    output = tmp_path / "report.html"
    generate_html_report(report, str(output))

    html = output.read_text(encoding="utf-8")

    return (
        html.split("<h2>Detected Threats</h2>", 1)[1]
        .split("<h2>Threat Timeline</h2>", 1)[0]
    )


def test_html_displays_first_and_last_seen_utc(tmp_path):
    first_seen = "2026-07-07T14:00:01+00:00"
    last_seen = "2026-07-07T14:05:01+00:00"

    section = _render_detected_threats(
        tmp_path,
        [
            _finding(
                title="Repeated Linux Service Manipulation Detected",
                first_seen=first_seen,
                last_seen=last_seen,
            )
        ],
    )

    assert "<th>First Seen (UTC)</th>" in section
    assert "<th>Last Seen (UTC)</th>" in section

    assert f"<td>{first_seen}</td>" in section
    assert f"<td>{last_seen}</td>" in section


def test_html_preserves_nanoseconds_and_converts_to_utc(tmp_path):
    section = _render_detected_threats(
        tmp_path,
        [
            _finding(
                first_seen=(
                    "2026-07-07T10:00:01.123456789-04:00"
                ),
                last_seen=(
                    "2026-07-07T14:05:01.987654321+00:00"
                ),
            )
        ],
    )

    assert (
        "<td>2026-07-07T14:00:01.123456789+00:00</td>"
        in section
    )
    assert (
        "<td>2026-07-07T14:05:01.987654321+00:00</td>"
        in section
    )


@pytest.mark.parametrize(
    ("first_seen", "last_seen"),
    [
        (None, None),
        ("2026-07-07T14:00:01", "invalid timestamp"),
        ("<script>alert(1)</script>", "api_key=PRIVATE_TOKEN"),
    ],
)
def test_html_uses_unknown_for_unreliable_time(
    tmp_path,
    first_seen,
    last_seen,
):
    section = _render_detected_threats(
        tmp_path,
        [
            _finding(
                first_seen=first_seen,
                last_seen=last_seen,
            )
        ],
    )

    assert "<th>First Seen (UTC)</th>" in section
    assert "<th>Last Seen (UTC)</th>" in section

    assert section.count("<td>Unknown</td>") == 2

    # Untrusted or secret-like input must not leak.
    assert "<script>" not in section
    assert "PRIVATE_TOKEN" not in section

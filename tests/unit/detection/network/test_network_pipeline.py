import csv
import json

from datetime import datetime, timezone

from src.detection.network.network_pipeline import (
    run_network_detection_pipeline,
)


def test_network_pipeline_returns_empty_result_when_pcap_is_missing(
    tmp_path,
):
    result = run_network_detection_pipeline(
        pcap_file=str(tmp_path / "missing.pcap"),
        pcap_csv_file=str(tmp_path / "network.csv"),
        whitelist_file="config/whitelist.json",
        critical_ports_file="config/critical_ports.json",
    )

    assert result.events == []
    assert result.findings == []
    assert result.statistics == {
        "total_network_events": 0,
        "protocols": {},
        "dns_queries": [],
        "http_requests": 0,
    }


def test_network_pipeline_preserves_event_times_through_correlation(
    tmp_path,
    monkeypatch,
):
    pcap_file = tmp_path / "capture.pcap"
    pcap_file.write_bytes(b"")

    csv_file = tmp_path / "network.csv"
    whitelist_file = tmp_path / "whitelist.json"
    critical_ports_file = tmp_path / "critical_ports.json"

    whitelist_file.write_text(
        json.dumps({
            "allowed_ips": [
                "192.0.2.10",
                "192.0.2.11",
                "203.0.113.80",
            ]
        }),
        encoding="utf-8",
    )

    critical_ports_file.write_text(
        json.dumps({"critical_ports": [3389]}),
        encoding="utf-8",
    )

    def epoch(hour, minute, fraction="000000000"):
        dt = datetime(
            2026, 7, 16, hour, minute,
            tzinfo=timezone.utc,
        )
        return f"{int(dt.timestamp())}.{fraction}"

    earliest = epoch(9, 0, "123456789")
    middle = epoch(9, 3)
    latest = epoch(9, 7, "987654321")
    unrelated_time = epoch(6, 0)

    rows = [
        {
            "frame.time_epoch": latest,
            "ip.src": "192.0.2.10",
            "ip.dst": "198.51.100.20",
            "_ws.col.Protocol": "TCP",
            "tcp.srcport": "51514",
            "tcp.dstport": "3389",
        },
        {
            "frame.time_epoch": unrelated_time,
            "ip.src": "192.0.2.11",
            "ip.dst": "203.0.113.80",
            "_ws.col.Protocol": "TCP",
            "tcp.srcport": "51514",
            "tcp.dstport": "443",
        },
        {
            "frame.time_epoch": middle,
            "ip.src": "192.0.2.10",
            "ip.dst": "198.51.100.20",
            "_ws.col.Protocol": "TCP",
            "tcp.srcport": "51514",
            "tcp.dstport": "3389",
        },
        {
            "frame.time_epoch": earliest,
            "ip.src": "192.0.2.10",
            "ip.dst": "198.51.100.20",
            "_ws.col.Protocol": "TCP",
            "tcp.srcport": "51514",
            "tcp.dstport": "3389",
        },
    ]


    def fake_export(input_path, output_path):
        assert input_path == str(pcap_file)

        with open(
            output_path,
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "frame.time_epoch",
                    "ip.src",
                    "ip.dst",
                    "_ws.col.Protocol",
                    "tcp.srcport",
                    "tcp.dstport",
                ],
            )
            writer.writeheader()
            writer.writerows(rows)

    monkeypatch.setattr(
        "src.detection.network.network_pipeline.export_pcap_to_csv",
        fake_export,
    )

    # Keep this integration test independent of external IOC feeds.
    monkeypatch.setattr(
        "src.detection.network.network_ioc_detector.get_iocs",
        lambda: [],
    )

    result = run_network_detection_pipeline(
        pcap_file=str(pcap_file),
        pcap_csv_file=str(csv_file),
        whitelist_file=str(whitelist_file),
        critical_ports_file=str(critical_ports_file),
    )

    # The real CSV parser must preserve source epoch strings.
    assert len(result.events) == 4

    assert [
        event.timestamp
        for event in result.events
    ] == [
        latest,
        unrelated_time,
        middle,
        earliest,
    ]

    expected_first = (
        "2026-07-16T09:00:00.123456789+00:00"
    )
    expected_last = (
        "2026-07-16T09:07:00.987654321+00:00"
    )

    expected_titles = {
        "Unknown Network IP Detected",
        "Critical Network Port Detected",
        "Correlated Network Threat Detected",
    }

    for title in expected_titles:
        matching = [
            finding
            for finding in result.findings
            if finding.title == title
            and finding.ip == "198.51.100.20"
        ]

        assert len(matching) == 1

        assert matching[0].first_seen == expected_first
        assert matching[0].last_seen == expected_last

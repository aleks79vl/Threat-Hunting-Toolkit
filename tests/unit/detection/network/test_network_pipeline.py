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
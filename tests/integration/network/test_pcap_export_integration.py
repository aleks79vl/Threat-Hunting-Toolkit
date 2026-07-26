from pathlib import Path

import pytest

from src.parsers.pcap_exporter import export_pcap_to_csv
from src.parsers.wireshark_csv_parser import parse_wireshark_csv
from src.utils.tshark_dependency import is_tshark_available


PCAP_FILE = Path("data/raw/pcap/sample.pcap")
PCAPNG_FILE = Path("data/raw/pcap/sample.pcapng")


def get_sample_capture():
    if PCAP_FILE.exists():
        return PCAP_FILE

    if PCAPNG_FILE.exists():
        return PCAPNG_FILE

    return None


@pytest.mark.integration
def test_export_sample_pcap_to_csv_and_parse():
    if not is_tshark_available():
        pytest.skip("TShark is not available")

    sample_capture = get_sample_capture()

    if sample_capture is None:
        pytest.skip(
            "Sample PCAP/PCAPNG file is not available"
        )

    output_file = Path(
        "data/processed/pcap/test_sample.csv"
    )

    export_pcap_to_csv(
        str(sample_capture),
        str(output_file),
    )

    assert output_file.exists()

    events = parse_wireshark_csv(
        str(output_file)
    )

    assert len(events) > 0
    assert any(
        event.src_ip or event.dst_ip
        for event in events
    )
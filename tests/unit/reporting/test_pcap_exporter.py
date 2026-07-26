from pathlib import Path

import pytest

from src.parsers.pcap_exporter import (
    _validate_pcap_file,
    export_pcap_to_csv,
    export_pcap_to_json,
)


def test_validate_pcap_file_accepts_pcap(tmp_path):
    pcap_file = tmp_path / "capture.pcap"
    pcap_file.write_bytes(b"")

    result = _validate_pcap_file(str(pcap_file))

    assert result == pcap_file


def test_validate_pcap_file_accepts_pcapng(tmp_path):
    pcap_file = tmp_path / "capture.pcapng"
    pcap_file.write_bytes(b"")

    result = _validate_pcap_file(str(pcap_file))

    assert result == pcap_file


def test_validate_pcap_file_not_found():
    with pytest.raises(FileNotFoundError):
        _validate_pcap_file("missing_capture.pcap")


def test_validate_pcap_file_rejects_invalid_format(
    tmp_path,
):
    invalid_file = tmp_path / "capture.txt"
    invalid_file.write_text("not a capture",encoding="utf-8",)

    with pytest.raises(ValueError):
        _validate_pcap_file(str(invalid_file))


def test_export_pcap_functions_exist():
    assert callable(export_pcap_to_csv)
    assert callable(export_pcap_to_json)
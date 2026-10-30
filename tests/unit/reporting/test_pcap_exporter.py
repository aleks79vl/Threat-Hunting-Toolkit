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


def test_export_pcap_to_csv_preserves_epoch_field_configuration(
    tmp_path,
    monkeypatch,
):
    pcap_file = tmp_path / "capture.pcap"
    pcap_file.write_bytes(b"")

    csv_file = tmp_path / "output" / "network.csv"

    captured_commands = []

    def fake_run(command, *, stdout, stderr, text, check):
        captured_commands.append(command)

        assert text is True
        assert check is True

        stdout.write(
            "frame.time_epoch,ip.src\n"
            "1784202420.123456789,192.0.2.10\n"
        )

    monkeypatch.setattr(
        "src.parsers.pcap_exporter._get_tshark_path",
        lambda: "tshark",
    )

    monkeypatch.setattr(
        "src.parsers.pcap_exporter.subprocess.run",
        fake_run,
    )

    export_pcap_to_csv(
        str(pcap_file),
        str(csv_file),
    )

    assert len(captured_commands) == 1

    command = captured_commands[0]

    assert command[command.index("-T") + 1] == "fields"
    assert command[command.index("-r") + 1] == str(pcap_file)

    exported_fields = [
        command[index + 1]
        for index, argument in enumerate(command[:-1])
        if argument == "-e"
    ]

    assert exported_fields[0] == "frame.time_epoch"

    assert csv_file.exists()
    assert "1784202420.123456789" in csv_file.read_text(
        encoding="utf-8"
    )

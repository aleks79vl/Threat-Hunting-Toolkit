import json
import subprocess
from pathlib import Path

from src.utils.tshark_dependency import find_tshark


PCAP_FIELDS = [
    "frame.time_epoch",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "_ws.col.Protocol",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "http.host",
    "http.request.uri",
]


def _validate_pcap_file(input_path: str) -> Path:
    """
    Validate PCAP input file.
    """

    pcap_file = Path(input_path)

    if not pcap_file.exists():
        raise FileNotFoundError(f"PCAP file not found: {input_path}")

    if pcap_file.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError(
            "Unsupported capture format. "
            "Expected .pcap or .pcapng"
        )

    return pcap_file


def _get_tshark_path() -> str:
    """
    Return tshark executable path.
    """

    tshark_path = find_tshark()

    if tshark_path is None:
        raise RuntimeError("TShark dependency is not available.")

    return tshark_path


def export_pcap_to_csv(
    input_path: str,
    output_path: str,
) -> None:
    """
    Export selected PCAP fields to CSV.
    """

    pcap_file = _validate_pcap_file(input_path)
    tshark_path = _get_tshark_path()

    output_file = Path(output_path)

    output_file.parent.mkdir(parents=True,exist_ok=True,)

    command = [
        tshark_path,
        "-r",
        str(pcap_file),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]

    for field in PCAP_FIELDS:
        command.extend(
            [
                "-e",
                field,
            ]
        )

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as file:
        subprocess.run(
            command,
            stdout=file,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )


def export_pcap_to_json(
    input_path: str,
    output_path: str,
) -> None:
    """
    Export PCAP packets to JSON.
    """

    pcap_file = _validate_pcap_file(input_path)
    tshark_path = _get_tshark_path()

    output_file = Path(output_path)

    output_file.parent.mkdir(parents=True,exist_ok=True,)

    command = [
        tshark_path,
        "-r",
        str(pcap_file),
        "-T",
        "json",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    packets = json.loads(result.stdout)

    with open(output_file,"w",encoding="utf-8",) as file:
        json.dump(packets,file,indent=4,)
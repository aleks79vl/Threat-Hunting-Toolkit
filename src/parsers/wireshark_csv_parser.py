import csv

from src.models.network_event import NetworkEvent


def parse_wireshark_csv(file_path: str) -> list[NetworkEvent]:
    """
    Parse tshark-exported CSV into NetworkEvent objects.
    """

    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            src_port = row.get("tcp.srcport") or row.get("udp.srcport") or ""
            dst_port = row.get("tcp.dstport") or row.get("udp.dstport") or ""

            src_ip = row.get("ip.src") or row.get("ipv6.src") or ""
            dst_ip = row.get("ip.dst") or row.get("ipv6.dst") or ""

            event = NetworkEvent(
                timestamp=row.get("frame.time_epoch", ""),
                src_mac=row.get("eth.src", ""),
                dst_mac=row.get("eth.dst", ""),
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=row.get("_ws.col.Protocol", ""),
                src_port=src_port,
                dst_port=dst_port,
                dns_query=row.get("dns.qry.name", ""),
                http_host=row.get("http.host", ""),
                http_uri=row.get("http.request.uri", ""),
                arp_src_ip=row.get("arp.src.proto_ipv4", ""),
                arp_dst_ip=row.get("arp.dst.proto_ipv4", ""),
                arp_src_mac=row.get("arp.src.hw_mac", ""),
                arp_dst_mac=row.get("arp.dst.hw_mac", ""),
            )

            events.append(event)

    return events
from dataclasses import dataclass


@dataclass
class NetworkEvent:
    """
    Normalized network event extracted from PCAP/Wireshark data.
    """

    timestamp: str
    src_ip: str = ""
    dst_ip: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    protocol: str = ""
    src_port: str = ""
    dst_port: str = ""
    dns_query: str = ""
    http_host: str = ""
    http_uri: str = ""
    arp_src_ip: str = ""
    arp_dst_ip: str = ""
    arp_src_mac: str = ""
    arp_dst_mac: str = ""
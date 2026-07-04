from collections import Counter


def generate_network_statistics(network_events):
    """
    Generate summary statistics for parsed PCAP/Wireshark events.
    """

    protocols = Counter()
    dns_queries = set()
    http_requests = 0

    for event in network_events:
        if event.protocol:
            protocols[event.protocol] += 1

        if event.dns_query:
            dns_queries.add(event.dns_query)

        if event.http_host or event.http_uri:
            http_requests += 1

    return {
        "total_network_events": len(network_events),
        "protocols": dict(protocols),
        "dns_queries": sorted(dns_queries),
        "http_requests": http_requests,
    }
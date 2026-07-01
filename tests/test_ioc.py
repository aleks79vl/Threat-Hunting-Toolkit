from src.models.ioc import IOC


def test_create_ip_ioc():
    ioc = IOC(
        value="185.220.101.1",
        ioc_type="ip",
        source="Local IOC Database",
        confidence="high",
        description="Known malicious Tor exit node",
    )

    assert ioc.value == "185.220.101.1"
    assert ioc.ioc_type == "ip"
    assert ioc.source == "Local IOC Database"
    assert ioc.confidence == "high"


def test_create_domain_ioc():
    ioc = IOC(
        value="evil-example.com",
        ioc_type="domain",
        source="Local IOC Database",
    )

    assert ioc.ioc_type == "domain"


def test_default_values():
    ioc = IOC(
        value="bad.exe",
        ioc_type="hash",
        source="Internal",
    )

    assert ioc.confidence == "medium"
    assert ioc.description == ""

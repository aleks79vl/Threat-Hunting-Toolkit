from src.intelligence.ioc_loader import load_database
from src.intelligence.ioc_loader import get_iocs


def test_load_database():

    database = load_database()

    assert "ips" in database
    assert "domains" in database
    assert "urls" in database
    assert "hashes" in database


def test_get_iocs():

    iocs = get_iocs()

    assert len(iocs) > 0


def test_ip_ioc_exists():

    iocs = get_iocs()

    assert any(ioc.ioc_type == "ip" for ioc in iocs)


def test_hash_ioc_exists():

    iocs = get_iocs()

    assert any(ioc.ioc_type == "hash" for ioc in iocs)
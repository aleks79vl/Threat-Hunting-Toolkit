import pytest

from src.intelligence.ioc_comparison import ioc_matches


@pytest.mark.parametrize(
    "ioc_type,indicator,observed,expected",
    [
        # IP: exact matching and canonical IPv6
        ("ip", "192.0.2.1", "192.0.2.1", True),
        ("ip", "192.0.2.1", "192.0.2.10", False),
        (
            "ip",
            "2001:db8::1",
            "2001:0db8:0:0:0:0:0:1",
            True,
        ),
        ("ip", "invalid-ip", "invalid-ip", False),

        # Domain: DNS-label boundaries
        (
            "domain",
            "evil-example.com",
            "EVIL-EXAMPLE.COM.",
            True,
        ),
        (
            "domain",
            "evil-example.com",
            "sub.evil-example.com",
            True,
        ),
        (
            "domain",
            "evil-example.com",
            "not-evil-example.com",
            False,
        ),
        (
            "domain",
            "evil-example.com",
            "evil-example.com.attacker.test",
            False,
        ),
        (
            "domain",
            "evil-example.com",
            "evil-example.com:443",
            True,
        ),

        # URL: structural comparison
        ("url", "/shell.php", "/shell.php", True),
        ("url", "/shell.php", "/shell.php?x=1", True),
        ("url", "/shell.php", "/shell.php.bak", False),
        (
            "url",
            "https://example.test/shell.php",
            "https://EXAMPLE.TEST/shell.php",
            True,
        ),
        (
            "url",
            "https://example.test/shell.php",
            "https://example.test:443/shell.php",
            True,
        ),
        (
            "url",
            "/shell.php?mode=1",
            "/shell.php?mode=2",
            False,
        ),

        # Hash: complete hexadecimal tokens
        (
            "hash",
            "44d88612fea8a8f36de82e1278abb02f",
            "44D88612FEA8A8F36DE82E1278ABB02F",
            True,
        ),
        (
            "hash",
            "44d88612fea8a8f36de82e1278abb02f",
            "44d88612fea8a8f36de82e1278abb02f0",
            False,
        ),
        ("hash", "a" * 64, "A" * 64, True),
    ],
)
def test_core08_comparison_contract(
    ioc_type,
    indicator,
    observed,
    expected,
):
    assert ioc_matches(
        ioc_type,
        indicator,
        observed,
    ) is expected

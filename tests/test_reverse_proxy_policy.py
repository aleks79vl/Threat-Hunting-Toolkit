import pytest

from src.detection.web.reverse_proxy_policy import (
    ReverseProxyPolicy,
)


def test_trusted_proxy_policy_accepts_ip_and_subnet():
    policy = ReverseProxyPolicy(
        trusted_proxy_networks=[
            "10.0.0.5",
            "192.168.10.0/24",
        ]
    )

    assert policy.is_trusted_proxy("10.0.0.5") is True
    assert policy.is_trusted_proxy("192.168.10.44") is True


def test_trusted_proxy_policy_rejects_unknown_or_invalid_ip():
    policy = ReverseProxyPolicy(
        trusted_proxy_networks=["10.0.0.0/24"]
    )

    assert policy.is_trusted_proxy("203.0.113.44") is False
    assert policy.is_trusted_proxy("not-an-ip") is False


def test_trusted_proxy_policy_requires_positive_chain_limit():
    with pytest.raises(ValueError):
        ReverseProxyPolicy(max_proxy_chain_length=0)

def test_resolve_client_ip_uses_forwarded_header_from_trusted_proxy():
    policy = ReverseProxyPolicy(
        trusted_proxy_networks=["10.0.0.0/24"]
    )

    client_ip = policy.resolve_client_ip(
        connecting_ip="10.0.0.5",
        forwarded_for=["198.51.100.10", "10.0.0.4"],
    )

    assert client_ip == "198.51.100.10"


def test_resolve_client_ip_ignores_header_from_untrusted_client():
    policy = ReverseProxyPolicy(
        trusted_proxy_networks=["10.0.0.0/24"]
    )

    client_ip = policy.resolve_client_ip(
        connecting_ip="203.0.113.44",
        forwarded_for=["198.51.100.10"],
    )

    assert client_ip == "203.0.113.44"

def test_resolve_client_ip_skips_invalid_forwarded_value():
    policy = ReverseProxyPolicy(
        trusted_proxy_networks=["10.0.0.0/24"]
    )

    client_ip = policy.resolve_client_ip(
        connecting_ip="10.0.0.5",
        forwarded_for=["invalid-ip", "198.51.100.10"],
    )

    assert client_ip == "198.51.100.10"
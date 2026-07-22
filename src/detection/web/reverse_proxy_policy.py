from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network


Network = IPv4Network | IPv6Network


@dataclass
class ReverseProxyPolicy:
    """
    Defines which reverse proxies are allowed to supply
    forwarded client-address headers.
    """

    trusted_proxy_networks: list[str] = field(
        default_factory=list
    )
    max_proxy_chain_length: int = 3

    _trusted_networks: tuple[Network, ...] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.max_proxy_chain_length < 1:
            raise ValueError(
                "max_proxy_chain_length must be at least 1"
            )

        self._trusted_networks = tuple(
            ip_network(network, strict=False)
            for network in self.trusted_proxy_networks
        )

    def is_trusted_proxy(self, address: str) -> bool:
        try:
            candidate = ip_address(address)
        except ValueError:
            return False

        return any(
            candidate in network
            for network in self._trusted_networks
        )

    def resolve_client_ip(
        self,
        connecting_ip: str,
        forwarded_for: list[str],
    ) -> str:
        """
        Return the original client IP only when the direct
        connection came from a trusted proxy.
        """

        if not self.is_trusted_proxy(connecting_ip):
            return connecting_ip

        for address in forwarded_for:
            try:
                ip_address(address)
            except ValueError:
                continue

            return address

        return connecting_ip
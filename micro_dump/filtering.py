"""Validated, composable packet filters."""

from __future__ import annotations

import ipaddress


PROTO_NAMES = {"tcp", "udp", "icmp", "icmp6", "arp"}


class FilterSpec:
    def __init__(self, ports: str | None = None, addresses: list[str] | None = None,
                 protocols: str | None = None):
        self.ports = self._ports(ports) if ports else set()
        self.addresses = [ipaddress.ip_network(item, strict=False) for item in (addresses or [])]
        self.protocols = self._protocols(protocols) if protocols else set()

    @staticmethod
    def _ports(value: str) -> set[int]:
        try:
            result = {int(item.strip()) for item in value.split(",")}
        except ValueError as exc:
            raise ValueError("--port expects comma-separated integers") from exc
        if not result or any(port < 1 or port > 65535 for port in result):
            raise ValueError("ports must be between 1 and 65535")
        return result

    @staticmethod
    def _protocols(value: str) -> set[str]:
        result = {item.strip().lower() for item in value.split(",")}
        if not result or result - PROTO_NAMES:
            bad = ", ".join(sorted(result - PROTO_NAMES))
            raise ValueError(f"unsupported protocol filter: {bad}; choose from tcp,udp,icmp,icmp6,arp")
        return result

    def matches(self, packet) -> bool:
        if self.ports and not ({packet.src_port, packet.dst_port} & self.ports):
            return False
        aliases = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "icmp6": "ICMP6", "arp": "ARP"}
        if self.protocols and packet.protocol.upper() not in {aliases[x] for x in self.protocols}:
            return False
        if self.addresses:
            matched = False
            for text in (packet.src, packet.dst):
                try:
                    address = ipaddress.ip_address(text.split("%", 1)[0])
                except ValueError:
                    continue
                if any(address.version == net.version and address in net for net in self.addresses):
                    matched = True
                    break
            if not matched:
                return False
        return True

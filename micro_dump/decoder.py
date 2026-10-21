"""Bounded, header-only Ethernet protocol decoder."""

from __future__ import annotations

import ipaddress
import socket
import struct
from typing import Iterable

from .model import Packet

ETHERNET = 0x0001
IPV4 = 0x0800
ARP = 0x0806
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
IPV6 = 0x86DD
MAX_IPV6_EXTENSIONS = 12
IPV6_AH = 51
IPV6_EXTENSION_HEADERS = (0, 43, 44, IPV6_AH, 60, 135, 139, 140, 253, 254)


def checksum16(data: bytes) -> int:
    """Return the Internet checksum of *data* (zero means valid incl. checksum)."""
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _need(raw: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(raw):
        raise ValueError(f"truncated {label}")


def _port_name(port: int, proto: str) -> str:
    names = {80: "http", 443: "https", 53: "dns", 22: "ssh", 25: "smtp", 123: "ntp"}
    return names.get(port, str(port))


def decode_frame(raw: bytes, timestamp: float = 0.0, interface: str = "offline", *,
                 check_checksums: bool = False) -> Packet:
    """Decode headers from an Ethernet frame without exposing its payload."""
    p = Packet(timestamp=timestamp, interface=interface, length=len(raw))
    p._detail.append(f"Captured length: {len(raw)} bytes")
    try:
        _need(raw, 0, 14, "Ethernet header")
        dst_mac, src_mac, ethertype = _mac(raw[0:6]), _mac(raw[6:12]), struct.unpack_from("!H", raw, 12)[0]
        p.src, p.dst = src_mac, dst_mac
        p._detail.extend([f"Ethernet source: {src_mac}", f"Ethernet destination: {dst_mac}"])
        offset = 14
        vlans: list[str] = []
        while ethertype in VLAN_TYPES and len(vlans) < 2:
            _need(raw, offset, 4, "VLAN header")
            tci, ethertype = struct.unpack_from("!HH", raw, offset)
            vlans.append(f"VID {tci & 0x0FFF}, PCP {(tci >> 13) & 7}")
            offset += 4
        if ethertype in VLAN_TYPES:
            raise ValueError("more than two VLAN tags; refusing deeper traversal")
        if vlans:
            p._detail.append("VLAN: " + "; ".join(vlans))
        p._detail.append(f"EtherType: 0x{ethertype:04x}")
        if ethertype == IPV4:
            _decode_ipv4(raw, offset, p, check_checksums)
        elif ethertype == IPV6:
            _decode_ipv6(raw, offset, p, check_checksums)
        elif ethertype == ARP:
            _decode_arp(raw, offset, p)
        else:
            p.protocol = {0x8863: "PPPoE", 0x8864: "PPPoE"}.get(ethertype, "Ethernet")
            p.info = f"EtherType 0x{ethertype:04x}"
    except (ValueError, struct.error, ipaddress.AddressValueError) as exc:
        p.malformed = True
        p.truncated = "truncated" in str(exc).lower()
        p.protocol = p.protocol if p.protocol != "UNKNOWN" else "MALFORMED"
        p.info = str(exc)
        p._detail.append(f"Decode error: {exc}")
    return p


def _decode_arp(raw: bytes, offset: int, p: Packet) -> None:
    _need(raw, offset, 8, "ARP header")
    htype, ptype, hlen, plen, oper = struct.unpack_from("!HHBBH", raw, offset)
    size = 8 + 2 * hlen + 2 * plen
    _need(raw, offset, size, "ARP addresses")
    pos = offset + 8
    sha = raw[pos:pos + hlen]; pos += hlen
    spa = raw[pos:pos + plen]; pos += plen
    tha = raw[pos:pos + hlen]; pos += hlen
    tpa = raw[pos:pos + plen]
    if htype == 1 and ptype == IPV4 and hlen == 6 and plen == 4:
        src, dst = str(ipaddress.IPv4Address(spa)), str(ipaddress.IPv4Address(tpa))
        p.src, p.dst = src, dst
        p.info = f"{('request' if oper == 1 else 'reply' if oper == 2 else f'op {oper}')} {src} → {dst}"
        p._detail.extend([f"ARP operation: {oper}", f"Sender: {src} ({_mac(sha)})", f"Target: {dst} ({_mac(tha)})"])
    else:
        p.info = f"ARP operation {oper}, hardware/protocol lengths {hlen}/{plen}"
        p._detail.append(f"ARP hardware type {htype}, protocol type 0x{ptype:04x}")
    p.protocol = "ARP"
    p.checksum = "n/a"


def _decode_ipv4(raw: bytes, off: int, p: Packet, verify: bool) -> None:
    _need(raw, off, 20, "IPv4 header")
    first, tos, total_len, ident, frag, ttl, proto_num, csum, src_b, dst_b = struct.unpack_from("!BBHHHBBH4s4s", raw, off)
    version, ihl = first >> 4, (first & 0x0F) * 4
    if version != 4 or ihl < 20:
        raise ValueError("invalid IPv4 version or header length")
    _need(raw, off, ihl, "IPv4 options/header")
    if total_len < ihl:
        raise ValueError("invalid IPv4 total length smaller than header")
    if off + total_len > len(raw):
        raise ValueError("truncated IPv4 packet according to total length")
    src, dst = str(ipaddress.IPv4Address(src_b)), str(ipaddress.IPv4Address(dst_b))
    p.src, p.dst = src, dst
    p._detail.extend([f"IPv4 source: {src}", f"IPv4 destination: {dst}", f"TTL: {ttl}", f"IPv4 header length: {ihl} bytes", f"IPv4 total length: {total_len}", f"IPv4 ID: {ident}"])
    if verify:
        ip_checksum = "IPv4 ok" if checksum16(raw[off:off + ihl]) == 0 else "IPv4 BAD"
    else:
        ip_checksum = "unchecked"
    frag_off, more = frag & 0x1FFF, bool(frag & 0x2000)
    if frag_off or more:
        p._detail.append(f"IPv4 fragment: offset {frag_off * 8} bytes, MF={int(more)}, DF={int(bool(frag & 0x4000))}")
    p.checksum = ip_checksum
    p.protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, f"IPv4/{proto_num}")
    if frag_off:
        p.info = f"fragment offset {frag_off * 8} bytes" + (", more fragments" if more else "")
        return
    if more:
        p.info = f"fragment offset 0 bytes, more fragments"
        return
    _decode_transport(raw, off + ihl, off + total_len, proto_num, p, verify,
                      src_b + dst_b + struct.pack("!BBH", 0, proto_num, total_len - ihl), ipv6=False)


def _decode_ipv6(raw: bytes, off: int, p: Packet, verify: bool) -> None:
    _need(raw, off, 40, "IPv6 header")
    first_word, payload_len, next_header, hop_limit = struct.unpack_from("!IHBB", raw, off)
    if first_word >> 28 != 6:
        raise ValueError("invalid IPv6 version")
    end = off + 40 + payload_len
    if end > len(raw):
        raise ValueError("truncated IPv6 packet according to payload length")
    src_b, dst_b = raw[off + 8:off + 24], raw[off + 24:off + 40]
    src, dst = str(ipaddress.IPv6Address(src_b)), str(ipaddress.IPv6Address(dst_b))
    p.src, p.dst = src, dst
    p._detail.extend([f"IPv6 source: {src}", f"IPv6 destination: {dst}", f"Hop limit: {hop_limit}", f"IPv6 payload length: {payload_len}"])
    pos = off + 40
    ext_count = 0
    fragment_seen = False
    fragment_offset = 0
    fragment_more = False
    while next_header in IPV6_EXTENSION_HEADERS:
        ext_count += 1
        if ext_count > MAX_IPV6_EXTENSIONS:
            raise ValueError("IPv6 extension-header chain exceeds safe traversal limit")
        if next_header == 44:
            _need(raw, pos, 8, "IPv6 fragment header")
            following, _, fragword, frag_id = struct.unpack_from("!BBHI", raw, pos)
            fragment_offset = ((fragword >> 3) & 0x1FFF) * 8
            fragment_more = bool(fragword & 1)
            fragment_seen = True
            p._detail.append(f"IPv6 fragment: offset {fragment_offset} bytes, M={int(fragment_more)}, ID={frag_id}")
            size = 8
        elif next_header == IPV6_AH:
            _need(raw, pos, 2, "IPv6 AH header")
            following, length_byte = struct.unpack_from("!BB", raw, pos)
            size = (length_byte + 2) * 4
        else:
            _need(raw, pos, 2, "IPv6 extension header")
            following, length_byte = struct.unpack_from("!BB", raw, pos)
            size = (length_byte + 1) * 8
        _need(raw, pos, size, "IPv6 extension header body")
        if size < 8:
            raise ValueError("invalid IPv6 extension-header length")
        p._detail.append(f"IPv6 extension header {next_header}, {size} bytes")
        pos += size
        next_header = following
        if fragment_seen and fragment_offset:
            p.protocol = {6: "TCP", 17: "UDP", 58: "ICMP6"}.get(next_header, f"IPv6/{next_header}")
            p.info = f"fragment offset {fragment_offset} bytes" + (", more fragments" if fragment_more else "")
            return
    p.protocol = {6: "TCP", 17: "UDP", 58: "ICMP6"}.get(next_header, f"IPv6/{next_header}")
    pseudo = src_b + dst_b + struct.pack("!I3xB", end - pos, next_header)
    _decode_transport(raw, pos, end, next_header, p, verify, pseudo, ipv6=True)


def _decode_transport(raw: bytes, off: int, end: int, proto: int, p: Packet, verify: bool,
                      pseudo: bytes, *, ipv6: bool) -> None:
    ip_checksum = None if ipv6 else next((piece.strip() for piece in p.checksum.split(";") if piece.strip().startswith("IPv4 ")), None)
    if proto == 6:
        _need(raw[:end], off, 20, "TCP header")
        sport, dport, seq, ack, dataoff_flags, window, csum, urg = struct.unpack_from("!HHIIHHHH", raw, off)
        hlen = (dataoff_flags >> 12) * 4
        if hlen < 20:
            raise ValueError("invalid TCP header length")
        _need(raw[:end], off, hlen, "TCP options/header")
        flagword = dataoff_flags & 0x01FF
        flags = [(bit, name) for bit, name in ((0x002, "SYN"), (0x004, "RST"), (0x001, "FIN"), (0x010, "ACK"), (0x008, "PSH"), (0x020, "URG"), (0x040, "ECE"), (0x080, "CWR"), (0x100, "NS")) if flagword & bit]
        p.flags = tuple(name for _, name in flags)
        p.src_port, p.dst_port = sport, dport
        p.info = f"{_port_name(sport, 'tcp')} → {_port_name(dport, 'tcp')} seq={seq} ack={ack} win={window}"
        p._detail.extend([f"TCP ports: {sport} → {dport}", f"TCP header length: {hlen} bytes", f"TCP sequence: {seq}", f"TCP acknowledgement: {ack}", f"TCP window: {window}", f"TCP flags: {', '.join(p.flags) or 'none'}"])
        if verify:
            segment = raw[off:end]
            transport_checksum = "TCP ok" if checksum16(pseudo + segment) == 0 else "TCP BAD"
        else:
            transport_checksum = "unchecked"
        p.checksum = f"{ip_checksum}; {transport_checksum}" if ip_checksum else transport_checksum
    elif proto == 17:
        _need(raw[:end], off, 8, "UDP header")
        sport, dport, length, csum = struct.unpack_from("!HHHH", raw, off)
        if length < 8:
            raise ValueError("invalid UDP length smaller than header")
        if off + length > end:
            raise ValueError("truncated UDP datagram according to UDP length")
        p.src_port, p.dst_port = sport, dport
        p.info = f"{_port_name(sport, 'udp')} → {_port_name(dport, 'udp')} length={length}"
        p._detail.extend([f"UDP ports: {sport} → {dport}", f"UDP length: {length}"])
        if verify:
            if csum == 0 and not ipv6:
                transport_checksum = "UDP absent"
            elif csum == 0 and ipv6:
                transport_checksum = "UDP BAD (zero checksum in IPv6)"
            else:
                transport_checksum = "UDP ok" if checksum16(pseudo + raw[off:off + length]) == 0 else "UDP BAD"
        else:
            transport_checksum = "unchecked"
        p.checksum = f"{ip_checksum}; {transport_checksum}" if ip_checksum else transport_checksum
    elif proto in (1, 58):
        _need(raw[:end], off, 4, "ICMP header")
        typ, code, csum = struct.unpack_from("!BBH", raw, off)
        p.info = f"type={typ} code={code}"
        p._detail.append(f"ICMP type: {typ}, code: {code}")
        if verify:
            if proto == 1:
                transport_checksum = "ICMP ok" if checksum16(raw[off:end]) == 0 else "ICMP BAD"
            else:
                transport_checksum = "ICMPv6 ok" if checksum16(pseudo + raw[off:end]) == 0 else "ICMPv6 BAD"
        else:
            transport_checksum = "unchecked"
        p.checksum = f"{ip_checksum}; {transport_checksum}" if ip_checksum else transport_checksum

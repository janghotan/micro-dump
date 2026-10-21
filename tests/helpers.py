"""Construct synthetic Ethernet/IP packets; no socket/network use."""

import struct

from micro_dump.decoder import checksum16


MAC_DST = bytes.fromhex("001122334455")
MAC_SRC = bytes.fromhex("aabbccddeeff")


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return MAC_DST + MAC_SRC + struct.pack("!H", ethertype) + payload


def ipv4(payload: bytes, proto: int, *, options=b"", frag=0, src=b"\xc0\xa8\x01\x02", dst=b"\xc0\xa8\x01\x03", good_checksum=True) -> bytes:
    options += b"\0" * ((-len(options)) % 4)
    ihl = 20 + len(options)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | (ihl // 4), 0, ihl + len(payload), 1234, frag, 64, proto, 0, src, dst) + options
    if good_checksum:
        hdr = hdr[:10] + struct.pack("!H", checksum16(hdr)) + hdr[12:]
    return hdr + payload


def tcp(src=12345, dst=443, flags=0x002, payload=b"") -> bytes:
    word = (5 << 12) | flags
    return struct.pack("!HHIIHHHH", src, dst, 100, 0, word, 4096, 0, 0) + payload


def udp(src=12345, dst=53, payload=b"") -> bytes:
    return struct.pack("!HHHH", src, dst, 8 + len(payload), 0) + payload


def ipv6(payload: bytes, next_header: int, *, src=bytes.fromhex("20010db8000000000000000000000001"), dst=bytes.fromhex("20010db8000000000000000000000002"), hop=64) -> bytes:
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), next_header, hop, src, dst) + payload


def pcap_bytes(frames, *, endian="<", precision="us", linktype=1):
    magic = {("<", "us"): b"\xd4\xc3\xb2\xa1", (">", "us"): b"\xa1\xb2\xc3\xd4",
             ("<", "ns"): b"\x4d\x3c\xb2\xa1", (">", "ns"): b"\xa1\xb2\x3c\x4d"}[(endian, precision)]
    buf = bytearray(magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, linktype))
    base = 1_000_000 if precision == "us" else 1_000_000_000
    for i, frame in enumerate(frames):
        buf.extend(struct.pack(endian + "IIII", 100 + i, base // 2, len(frame), len(frame)))
        buf.extend(frame)
    return bytes(buf)

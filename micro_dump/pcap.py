"""Reader for classic Ethernet PCAP files (not PCAP-NG)."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO, Iterator

from .decoder import ETHERNET

MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
MAX_PACKET_SIZE = 16 * 1024 * 1024


class PcapError(ValueError):
    pass


class PcapReader:
    def __init__(self, source: str | Path | BinaryIO):
        self.source = source
        self._owned = not hasattr(source, "read")
        self.file: BinaryIO | None = None
        self.endian = "<"
        self.precision = 1_000_000
        self.snaplen = 0
        self.linktype = 0

    def __enter__(self):
        self.file = open(self.source, "rb") if self._owned else self.source  # type: ignore[arg-type,assignment]
        try:
            header = self.file.read(24)
            if len(header) != 24:
                raise PcapError("truncated PCAP global header (expected 24 bytes)")
            magic = header[:4]
            if magic not in MAGICS:
                raise PcapError("unsupported PCAP magic; expected classic PCAP (PCAP-NG is not supported)")
            self.endian, self.precision = MAGICS[magic]
            major, minor, zone, sigfigs, self.snaplen, network = struct.unpack(self.endian + "HHIIII", header[4:24])
            if (major, minor) != (2, 4):
                raise PcapError(f"unsupported PCAP version {major}.{minor}; expected 2.4")
            if self.snaplen <= 0 or self.snaplen > MAX_PACKET_SIZE:
                raise PcapError(f"unreasonable PCAP snapshot length: {self.snaplen}")
            if network != ETHERNET:
                raise PcapError(f"unsupported PCAP link type {network}; only Ethernet (1) is supported")
            self.linktype = network
            return self
        except BaseException:
            if self._owned and self.file:
                self.file.close()
                self.file = None
            raise

    def __exit__(self, exc_type, exc, tb):
        if self._owned and self.file:
            self.file.close()

    def __iter__(self) -> Iterator[tuple[float, bytes]]:
        if self.file is None:
            raise RuntimeError("PcapReader must be used as a context manager")
        while True:
            hdr = self.file.read(16)
            if not hdr:
                return
            if len(hdr) != 16:
                raise PcapError("truncated PCAP packet record header")
            sec, frac, incl_len, orig_len = struct.unpack(self.endian + "IIII", hdr)
            if incl_len > MAX_PACKET_SIZE or incl_len > self.snaplen:
                raise PcapError(f"unreasonable PCAP packet size: {incl_len} bytes")
            if incl_len > orig_len:
                raise PcapError(f"invalid PCAP record: captured length {incl_len} exceeds original {orig_len}")
            if frac >= self.precision:
                raise PcapError("invalid PCAP timestamp fraction")
            data = self.file.read(incl_len)
            if len(data) != incl_len:
                raise PcapError("truncated PCAP packet data")
            yield sec + frac / self.precision, data

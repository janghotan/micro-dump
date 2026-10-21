import struct
import unittest

from micro_dump.decoder import checksum16, decode_frame
from micro_dump.render import packet_line
from tests.helpers import ethernet, ipv4, ipv6, tcp, udp


class DecoderTests(unittest.TestCase):
    def test_vlan_and_double_vlan(self):
        raw = ethernet(struct.pack("!HH", 7, 0x8100) + struct.pack("!HH", 9, 0x0806) + b"\0" * 28, 0x8100)
        p = decode_frame(raw)
        self.assertIn("VLAN", " ".join(p.details()))
        self.assertEqual(p.protocol, "ARP")

    def test_ipv4_options_and_tcp_flags(self):
        raw = ethernet(ipv4(tcp(flags=0x002 | 0x010), 6, options=b"\x01\x01\x01\x01"))
        p = decode_frame(raw)
        self.assertEqual(p.src, "192.168.1.2")
        self.assertEqual(p.src_port, 12345)
        self.assertEqual(p.flags, ("SYN", "ACK"))
        self.assertIn("24 bytes", " ".join(p.details()))

    def test_udp_and_checksum(self):
        raw = ethernet(ipv4(udp(), 17))
        p = decode_frame(raw, check_checksums=True)
        self.assertEqual(p.protocol, "UDP")
        self.assertEqual(p.dst_port, 53)
        self.assertIn("IPv4 ok", p.checksum)

    def test_bad_ipv4_checksum_and_tcp_flags_render_with_colors(self):
        raw = ethernet(ipv4(tcp(flags=0x001), 6, good_checksum=False))
        p = decode_frame(raw, check_checksums=True)
        self.assertIn("IPv4 BAD", p.checksum)
        line = packet_line(p, color=True)
        self.assertIn("\x1b[33mFIN\x1b[0m", line)
        for flag, code in ((0x002, "32"), (0x004, "31")):
            packet = decode_frame(ethernet(ipv4(tcp(flags=flag), 6)))
            self.assertIn(f"\x1b[{code}m{packet.flags[0]}\x1b[0m", packet_line(packet, color=True))

    def test_ipv4_fragment_without_transport_guessing(self):
        p = decode_frame(ethernet(ipv4(b"not-a-header", 6, frag=0x2000)))
        self.assertEqual(p.protocol, "TCP")
        self.assertIsNone(p.src_port)
        self.assertIn("fragment", p.info)

    def test_ipv6_hop_by_hop_and_tcp(self):
        ext = struct.pack("!BB6s", 6, 0, b"\0" * 6)
        p = decode_frame(ethernet(ipv6(ext + tcp(flags=0x004), 0), 0x86DD))
        self.assertEqual(p.protocol, "TCP")
        self.assertEqual(p.flags, ("RST",))
        self.assertTrue(any("extension header" in d for d in p.details()))

    def test_ipv6_fragment_offset(self):
        frag = struct.pack("!BBHI", 6, 0, 8, 55)
        p = decode_frame(ethernet(ipv6(frag + tcp(), 44), 0x86DD))
        self.assertIn("fragment offset 8", p.info)
        self.assertIsNone(p.src_port)

    def test_arp(self):
        body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("aabbccddeeffc0a80102") + b"\0" * 6 + bytes.fromhex("c0a80103")
        p = decode_frame(ethernet(body, 0x0806))
        self.assertEqual(p.protocol, "ARP")
        self.assertIn("request", p.info)

    def test_icmp(self):
        p = decode_frame(ethernet(ipv4(struct.pack("!BBH4s", 8, 0, 0, b"\0" * 4), 1)))
        self.assertEqual(p.protocol, "ICMP")
        self.assertIn("type=8", p.info)

    def test_icmpv6_and_checksum_status(self):
        message = struct.pack("!BBH4s", 128, 0, 0, b"\0" * 4)
        p = decode_frame(ethernet(ipv6(message, 58), 0x86DD), check_checksums=True)
        self.assertEqual(p.protocol, "ICMP6")
        self.assertIn("ICMPv6 BAD", p.checksum)

    def test_truncated_and_malformed_never_crash(self):
        for raw in (b"", b"\0" * 10, ethernet(b"\x45"), ethernet(b"\x60" * 40, 0x86DD), ethernet(b"\x46" + b"\0" * 19)):
            p = decode_frame(raw)
            self.assertTrue(p.malformed)

    def test_ipv6_extension_limit(self):
        chain = bytearray()
        for _ in range(13):
            chain.extend(struct.pack("!BB6s", 0, 0, b"\0" * 6))
        p = decode_frame(ethernet(ipv6(bytes(chain), 0), 0x86DD))
        self.assertTrue(p.malformed)
        self.assertIn("limit", p.info)

    def test_checksum_odd_length(self):
        self.assertEqual(checksum16(b"\0\0"), 0xFFFF)


if __name__ == "__main__":
    unittest.main()

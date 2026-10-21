import io
import tempfile
import unittest
from pathlib import Path

from micro_dump.decoder import decode_frame
from micro_dump.filtering import FilterSpec
from micro_dump.pcap import PcapError, PcapReader
from micro_dump.render import PacketHistory, TerminalScreen, packet_line
from tests.helpers import ethernet, ipv4, pcap_bytes, tcp


class PcapTests(unittest.TestCase):
    def test_all_endian_and_precision_variants(self):
        frame = ethernet(ipv4(tcp(), 6))
        for endian in ("<", ">"):
            for precision in ("us", "ns"):
                with self.subTest(endian=endian, precision=precision), tempfile.TemporaryDirectory() as td:
                    path = Path(td) / "x.pcap"
                    path.write_bytes(pcap_bytes([frame], endian=endian, precision=precision))
                    with PcapReader(path) as reader:
                        packets = list(reader)
                    self.assertEqual(packets[0][1], frame)
                    self.assertAlmostEqual(packets[0][0], 100.5)

    def test_truncated_record_and_unsupported_link(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.pcap"
            path.write_bytes(pcap_bytes([b"abc"])[:-1])
            with PcapReader(path) as reader:
                with self.assertRaises(PcapError):
                    list(reader)
            path.write_bytes(pcap_bytes([], linktype=101))
            with self.assertRaisesRegex(PcapError, "link type"):
                with PcapReader(path):
                    pass

    def test_filter_ports_protocol_and_both_address_ends(self):
        packet = decode_frame(ethernet(ipv4(tcp(src=123, dst=443), 6)))
        self.assertTrue(FilterSpec("80,443", ["192.168.1.0/24"], "tcp").matches(packet))
        self.assertFalse(FilterSpec("80", None, None).matches(packet))
        self.assertFalse(FilterSpec(None, ["10.0.0.0/8"], None).matches(packet))
        self.assertTrue(FilterSpec(None, ["192.168.1.3"], None).matches(packet))

    def test_invalid_filters(self):
        for args in (("0", None, None), ("abc", None, None), (None, ["bad network"], None), (None, None, "gre")):
            with self.assertRaises(ValueError):
                FilterSpec(*args)

    def test_history_is_bounded_and_selection_clamped(self):
        history = PacketHistory(2)
        for i in range(3):
            history.add(decode_frame(ethernet(ipv4(tcp(), 6)), timestamp=i))
        self.assertEqual(len(history.items), 2)
        history.move(99)
        self.assertEqual(history.selected, 1)
        history.add(decode_frame(ethernet(ipv4(tcp(), 6)), timestamp=4))
        self.assertEqual(history.selected, 1)
        history.clear()
        self.assertIsNone(history.current)

    def test_line_does_not_expose_payload(self):
        frame = ethernet(ipv4(tcp(payload=b"SECRET_PAYLOAD"), 6))
        p = decode_frame(frame)
        line = packet_line(p, color=False)
        self.assertNotIn("SECRET", line)

    def test_terminal_screen_draws_selection_and_help_to_fake_screen(self):
        class FakeOutput(io.StringIO):
            def isatty(self):
                return True

        class FakeInput:
            def isatty(self):
                return True

        output = FakeOutput()
        screen = TerminalScreen(stdin=FakeInput(), stdout=output, color=False)
        packet = decode_frame(ethernet(ipv4(tcp(flags=0x002), 6)))
        history = PacketHistory(2)
        history.add(packet)
        screen.draw(history, interface="lo", source="test", paused=False, count=1, help_open=True)
        rendered = output.getvalue()
        self.assertIn("▶ ", rendered)
        self.assertIn("DETAILS", rendered)
        self.assertIn("Keys: Up/Down", rendered)
        self.assertNotIn("\x1b[32m", rendered)


if __name__ == "__main__":
    unittest.main()

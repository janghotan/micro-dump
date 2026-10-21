import argparse
import io
import tempfile
import unittest
from pathlib import Path

from micro_dump.cli import parser, run
from micro_dump.pcap import PcapReader
from tests.helpers import ethernet, ipv4, pcap_bytes, tcp


class CliTests(unittest.TestCase):
    def test_filter_validation_precedes_capture(self):
        args = parser().parse_args(["--interface", "eth0", "--port", "bad", "--plain"])
        called = []
        def factory(name):
            called.append(name)
            raise AssertionError("must not open capture for invalid filter")
        err = io.StringIO()
        result = run(args, capture_factory=factory, stderr=err)
        self.assertEqual(result, 2)
        self.assertEqual(called, [])
        self.assertIn("invalid filter", err.getvalue())

    def test_offline_plain_output_and_count(self):
        frames = [ethernet(ipv4(tcp(dst=443), 6)), ethernet(ipv4(tcp(dst=80), 6))]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.pcap"
            path.write_bytes(pcap_bytes(frames))
            args = parser().parse_args(["--read", str(path), "--plain", "--no-color", "--count", "1", "--proto", "tcp"])
            out = io.StringIO()
            err = io.StringIO()
            result = run(args, stdout=out, stderr=err)
            self.assertEqual(result, 0, err.getvalue())
            self.assertEqual(out.getvalue().count("TCP"), 1)
            self.assertNotIn("\x1b[", out.getvalue())

    def test_no_interface_is_clear_cli_error(self):
        args = parser().parse_args(["--plain"])
        err = io.StringIO()
        self.assertEqual(run(args, stderr=err), 2)
        self.assertIn("requires --interface", err.getvalue())

    def test_list_interfaces_injected(self):
        args = parser().parse_args(["--list-interfaces"])
        out = io.StringIO()
        self.assertEqual(run(args, interface_lister=lambda: ["lo", "eth-test"], stdout=out), 0)
        self.assertEqual(out.getvalue(), "lo\neth-test\n")


if __name__ == "__main__":
    unittest.main()

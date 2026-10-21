"""Command line entry point for Micro-Dump."""

from __future__ import annotations

import argparse
import os
import queue
import select
import sys
import threading
from typing import Callable

from . import __version__
from .capture import CaptureError, LiveCapture, list_interfaces
from .decoder import decode_frame
from .filtering import FilterSpec
from .pcap import PcapError, PcapReader
from .render import PacketHistory, TerminalScreen, render_plain


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="micro-dump", description="Inspect Ethernet packet headers on Linux or from classic PCAP files.")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--list-interfaces", action="store_true", help="list available network interfaces and exit")
    mode.add_argument("--read", metavar="FILE", help="replay a classic Ethernet PCAP file offline")
    ap.add_argument("--interface", metavar="NAME", help="interface for live capture (required for live capture)")
    ap.add_argument("--port", metavar="PORT[,PORT...]", help="match packets with either endpoint port")
    ap.add_argument("--ip", dest="addresses", action="append", metavar="ADDRESS[/PREFIX]", help="match source or destination IPv4/IPv6 address or CIDR; repeatable")
    ap.add_argument("--proto", metavar="PROTO[,PROTO...]", help="match tcp,udp,icmp,icmp6,arp")
    ap.add_argument("--check-sums", action="store_true", help="verify available IPv4, TCP, UDP, and ICMP checksums")
    ap.add_argument("--plain", action="store_true", help="print one summary per matching packet without the interactive UI")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    ap.add_argument("--count", type=int, metavar="N", help="stop after N matching packets")
    ap.add_argument("--history", type=int, default=500, metavar="N", help="maximum packets in TUI history (default: 500)")
    ap.add_argument("--version", action="version", version=f"micro-dump {__version__}")
    return ap


def run(args: argparse.Namespace, *, capture_factory=LiveCapture, interface_lister=list_interfaces,
        pcap_factory=PcapReader, screen_factory=TerminalScreen, stdout=None, stderr=None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        filt = FilterSpec(args.port, args.addresses, args.proto)
    except ValueError as exc:
        print(f"micro-dump: invalid filter: {exc}", file=stderr)
        return 2
    if args.count is not None and args.count < 1:
        print("micro-dump: --count must be greater than zero", file=stderr)
        return 2
    if args.history < 1:
        print("micro-dump: --history must be greater than zero", file=stderr)
        return 2
    if args.list_interfaces:
        try:
            names = interface_lister()
        except CaptureError as exc:
            print(f"micro-dump: {exc}", file=stderr)
            return 1
        for name in names:
            print(name, file=stdout)
        return 0
    if not args.read and not args.interface:
        print("micro-dump: live capture requires --interface NAME (or use --read FILE)", file=stderr)
        return 2
    if args.interface and args.read:
        print("micro-dump: --interface cannot be combined with --read", file=stderr)
        return 2

    plain = args.plain or not (getattr(sys.stdin, "isatty", lambda: False)() and getattr(stdout, "isatty", lambda: False)())
    color = not args.no_color and "NO_COLOR" not in os.environ
    history = PacketHistory(args.history)
    paused = False
    matched = 0
    stop = threading.Event()
    source = f"PCAP: {args.read}" if args.read else f"Interface: {args.interface}"

    def packet_source():
        if args.read:
            with pcap_factory(args.read) as reader:
                for timestamp, raw in reader:
                    yield timestamp, raw, "offline"
        else:
            with capture_factory(args.interface) as cap:
                for timestamp, raw in cap:
                    if stop.is_set():
                        break
                    yield timestamp, raw, args.interface

    try:
        if plain:
            for timestamp, raw, iface in packet_source():
                packet = decode_frame(raw, timestamp, iface, check_checksums=args.check_sums)
                if not filt.matches(packet):
                    continue
                render_plain(packet, color=color, stream=stdout)
                matched += 1
                if args.count is not None and matched >= args.count:
                    break
        else:
            with screen_factory(color=color) as screen:
                paused = False
                help_open = False
                incoming = queue.Queue(maxsize=128)
                done = threading.Event()
                error_box = []

                def pump():
                    try:
                        for item in packet_source():
                            while not stop.is_set():
                                try:
                                    incoming.put(item, timeout=0.1)
                                    break
                                except queue.Full:
                                    continue
                            if stop.is_set():
                                break
                    except BaseException as exc:
                        error_box.append(exc)
                    finally:
                        done.set()

                worker = threading.Thread(target=pump, daemon=True)
                worker.start()
                try:
                    while not stop.is_set():
                        if not paused:
                            try:
                                timestamp, raw, iface = incoming.get(timeout=0.05)
                            except queue.Empty:
                                if done.is_set():
                                    break
                                timestamp = raw = iface = None
                            if raw is not None:
                                packet = decode_frame(raw, timestamp, iface, check_checksums=args.check_sums)
                                if filt.matches(packet):
                                    history.add(packet)
                                    matched += 1
                                    if args.count is not None and matched >= args.count:
                                        screen.draw(history, interface=args.interface or "offline", source=source, paused=paused, count=matched, help_open=help_open)
                                        break
                        key = _read_key_nonblocking(screen)
                        if key is None:
                            screen.draw(history, interface=args.interface or "offline", source=source, paused=paused, count=matched, help_open=help_open)
                            continue
                        if key == "q":
                            break
                        if key == " ":
                            paused = not paused
                        elif key == "c":
                            history.clear()
                        elif key in ("UP", "k"):
                            history.move(-1)
                        elif key in ("DOWN", "j"):
                            history.move(1)
                        elif key == "?":
                            help_open = not help_open
                        screen.draw(history, interface=args.interface or "offline", source=source, paused=paused, count=matched, help_open=help_open)
                finally:
                    stop.set()
                    worker.join(timeout=1.0)
                if error_box:
                    exc = error_box[0]
                    if isinstance(exc, (CaptureError, PcapError, OSError)):
                        raise exc
                    raise RuntimeError(str(exc)) from exc
    except KeyboardInterrupt:
        stop.set()
    except (CaptureError, PcapError, OSError) as exc:
        stop.set()
        print(f"micro-dump: {exc}", file=stderr)
        return 1
    except RuntimeError as exc:
        stop.set()
        print(f"micro-dump: {exc}", file=stderr)
        return 2
    finally:
        stop.set()
    return 0


def _read_key_nonblocking(screen) -> str | None:
    """Read a key when available without blocking packet consumption."""
    try:
        ready, _, _ = select.select([screen.stdin], [], [], 0)
        if ready:
            return screen.key()
    except (OSError, ValueError):
        return None
    return None


def main(argv: list[str] | None = None) -> int:
    ap = parser()
    args = ap.parse_args(argv)
    # Parse --ip networks before any socket is opened (FilterSpec does this in run).
    return run(args)

"""Plain packet rendering and a small terminal-native interactive UI."""

from __future__ import annotations

import os
import shutil
import sys
import termios
import tty
from collections import deque


RESET = "\x1b[0m"
COLORS = {"green": "\x1b[32m", "red": "\x1b[31m", "yellow": "\x1b[33m", "cyan": "\x1b[36m", "dim": "\x1b[2m", "bold": "\x1b[1m"}


def paint(text: str, color: str | None, enabled: bool = True) -> str:
    return f"{COLORS[color]}{text}{RESET}" if enabled and color in COLORS else text


def packet_line(packet, *, color: bool = True) -> str:
    flags = " ".join(paint(flag, {"SYN": "green", "RST": "red", "FIN": "yellow"}.get(flag), color) for flag in packet.flags)
    flag_col = f" {flags}" if flags else ""
    checksum = paint(packet.checksum, "red" if "BAD" in packet.checksum else "dim", color)
    return (f"{packet.time_text:<12} {packet.interface[:8]:<8} {packet.src[:39]:<39} "
            f"{packet.endpoint_src[len(packet.src):]:<7} → {packet.dst[:39]:<39} "
            f"{packet.endpoint_dst[len(packet.dst):]:<7} {packet.protocol:<8}{flag_col} "
            f"{packet.length:>6}B {checksum}  {packet.info}")


def render_plain(packet, *, color: bool = True, stream=None) -> None:
    (stream or sys.stdout).write(packet_line(packet, color=color) + "\n")
    (stream or sys.stdout).flush()


class PacketHistory:
    """Fixed-size packet history, with selection kept valid after eviction."""
    def __init__(self, limit: int = 500):
        if limit < 1:
            raise ValueError("history limit must be positive")
        self.items = deque(maxlen=limit)
        self.selected = 0

    def add(self, packet) -> None:
        was_full = len(self.items) == self.items.maxlen
        self.items.append(packet)
        if not was_full and len(self.items) == 1:
            self.selected = 0
        elif was_full:
            self.selected = max(0, min(self.selected, len(self.items) - 1))

    def clear(self) -> None:
        self.items.clear()
        self.selected = 0

    def move(self, delta: int) -> None:
        if self.items:
            self.selected = max(0, min(len(self.items) - 1, self.selected + delta))

    @property
    def current(self):
        return self.items[self.selected] if self.items else None


class TerminalScreen:
    """Injectable terminal adapter for alternate-screen TUI and deterministic tests."""
    def __init__(self, stdin=None, stdout=None, *, color: bool = True):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.color = color and self.stdout.isatty() and "NO_COLOR" not in os.environ
        self.fd = None
        self.old_settings = None
        self.active = False

    def __enter__(self):
        if not self.stdin.isatty() or not self.stdout.isatty():
            raise RuntimeError("interactive mode requires a terminal; use --plain for redirected output")
        self.fd = self.stdin.fileno()
        self.old_settings = termios.tcgetattr(self.fd)
        tty.setcbreak(self.fd)
        self.stdout.write("\x1b[?1049h\x1b[?25l")
        self.stdout.flush()
        self.active = True
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        if self.active:
            try:
                self.stdout.write("\x1b[0m\x1b[?25h\x1b[?1049l")
                self.stdout.flush()
            finally:
                if self.fd is not None and self.old_settings is not None:
                    termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)
                self.active = False

    def key(self) -> str:
        ch = self.stdin.read(1)
        if ch != "\x1b":
            return ch
        # Decode common arrow-key escape sequences without blocking indefinitely.
        try:
            if self.stdin.read(1) == "[":
                return {"A": "UP", "B": "DOWN", "C": "RIGHT", "D": "LEFT"}.get(self.stdin.read(1), "ESC")
        except (OSError, ValueError):
            pass
        return "ESC"

    def draw(self, history: PacketHistory, *, interface: str, source: str, paused: bool, count: int, help_open: bool = False):
        size = shutil.get_terminal_size((80, 24))
        width, height = max(20, size.columns), max(6, size.lines)
        packets = list(history.items)
        list_rows = max(1, height - 9)
        start = max(0, min(history.selected - list_rows + 1, len(packets) - list_rows))
        end = min(len(packets), start + list_rows)
        out = ["\x1b[H\x1b[2J", paint(" MICRO-DUMP ", "bold", self.color) +
               f" {interface} · {source} · {'PAUSED' if paused else 'CAPTURING'} · matched {count} ",
               paint("─" * min(width, 130), "cyan", self.color)]
        headers = "TIME         INTERFACE SOURCE                                   SPORT   DESTINATION                              DPORT   PROTO    FLAGS LEN      CHECKSUM  INFO"
        out.append(headers[:width])
        for idx in range(start, end):
            line = _fit(packet_line(packets[idx], color=self.color), width)
            marker = "▶ " if idx == history.selected else "  "
            out.append(_fit(marker + line, width))
        while len(out) < 4 + list_rows:
            out.append("")
        out.append(paint("─" * min(width, 130), "cyan", self.color))
        current = history.current
        out.append(paint(" DETAILS ", "bold", self.color))
        if current:
            details = [f"{current.time_text}  {current.protocol}  {current.length} bytes  checksum: {current.checksum}",
                       f"{current.endpoint_src}  →  {current.endpoint_dst}", current.summary]
            details += current.details()
            for row in details[:max(0, height - len(out) - 2)]:
                out.append(_fit(row, width))
        elif not packets:
            out.append("Waiting for matching packets…")
        footer = " ↑/↓ select · Space pause/resume · c clear · ? help · q quit"
        if help_open:
            footer = "Keys: Up/Down select; Space pause/resume; c clear list; ? close help; q quit. Header-only inspection; payloads are never shown."
        out.append(paint(footer, "dim", self.color)[:width])
        self.stdout.write("\x1b[H" + "\n".join(out[:height]))
        self.stdout.flush()


def _fit(text: str, width: int) -> str:
    # Strip ANSI sequences before padding/clipping to avoid corrupting escape codes.
    import re
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    if len(clean) <= width:
        return text + " " * (width - len(clean))
    return clean[:max(0, width - 1)] + "…"

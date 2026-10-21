"""Linux AF_PACKET capture and interface discovery."""

from __future__ import annotations

import socket
import time

from .decoder import ETHERNET


class CaptureError(RuntimeError):
    pass


def list_interfaces() -> list[str]:
    try:
        return sorted({name for _, name in socket.if_nameindex()})
    except OSError as exc:
        raise CaptureError(f"could not enumerate network interfaces: {exc}") from exc


class LiveCapture:
    """Context-managed raw capture socket; never enables promiscuous mode."""
    def __init__(self, interface: str, *, socket_factory=socket.socket, clock=time.time):
        self.interface = interface
        self.socket_factory = socket_factory
        self.clock = clock
        self.sock: socket.socket | None = None

    def __enter__(self):
        if not hasattr(socket, "AF_PACKET"):
            raise CaptureError("live capture requires Linux AF_PACKET sockets")
        s = None
        try:
            s = self.socket_factory(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERNET))
            s.bind((self.interface, 0))
            s.settimeout(0.5)
            self.sock = s
            return self
        except PermissionError as exc:
            if s is not None:
                s.close()
            raise CaptureError("permission denied opening packet capture. Grant CAP_NET_RAW to the Python executable or run with suitable privileges; Micro-Dump never elevates privileges automatically.") from exc
        except OSError as exc:
            if s is not None:
                s.close()
            raise CaptureError(f"cannot capture on interface {self.interface!r}: {exc}") from exc

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def __iter__(self):
        if self.sock is None:
            raise RuntimeError("LiveCapture must be used as a context manager")
        while True:
            try:
                data = self.sock.recv(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                if self.sock is None:
                    return
                raise CaptureError(f"capture socket failed on {self.interface!r}: {exc}") from exc
            yield self.clock(), data

    def close(self):
        sock, self.sock = self.sock, None
        if sock is not None:
            sock.close()

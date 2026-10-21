"""Small packet metadata records shared by decoders and output backends."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class Packet:
    timestamp: float
    interface: str
    length: int
    src: str = "?"
    dst: str = "?"
    protocol: str = "UNKNOWN"
    src_port: int | None = None
    dst_port: int | None = None
    flags: tuple[str, ...] = ()
    info: str = ""
    checksum: str = "n/a"
    malformed: bool = False
    truncated: bool = False
    _detail: list[str] = field(default_factory=list, repr=False)

    @property
    def time_text(self) -> str:
        try:
            return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]
        except (OverflowError, OSError, ValueError):
            return f"{self.timestamp:.3f}"

    @property
    def endpoint_src(self) -> str:
        return f"{self.src}:{self.src_port}" if self.src_port is not None else self.src

    @property
    def endpoint_dst(self) -> str:
        return f"{self.dst}:{self.dst_port}" if self.dst_port is not None else self.dst

    @property
    def summary(self) -> str:
        flag_text = f" [{','.join(self.flags)}]" if self.flags else ""
        return f"{self.protocol}{flag_text} {self.info}".strip()

    def details(self) -> list[str]:
        return list(self._detail)

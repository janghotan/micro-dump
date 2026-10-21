"""Tiny PEP 517 backend using only Python's standard library.

It intentionally supports wheel builds only, avoiding build-time dependencies.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import zipfile
from pathlib import Path


ROOT = Path(__file__).parent
NAME = "micro_dump"
VERSION = "0.1.0"
DIST = "micro_dump-0.1.0.dist-info"


def get_requires_for_build_wheel(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    dest = Path(metadata_directory) / DIST
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "METADATA").write_text(_metadata(), encoding="utf-8")
    (dest / "WHEEL").write_text("Wheel-Version: 1.0\nGenerator: micro-dump\nRoot-Is-Purelib: true\nTag: py3-none-any\n", encoding="utf-8")
    (dest / "entry_points.txt").write_text("[console_scripts]\nmicro-dump = micro_dump.cli:main\n", encoding="utf-8")
    return DIST


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    filename = "micro_dump-0.1.0-py3-none-any.whl"
    entries: dict[str, bytes] = {}
    for path in (ROOT / NAME).glob("*.py"):
        entries[f"{NAME}/{path.name}"] = path.read_bytes()
    entries[f"{DIST}/METADATA"] = _metadata().encode()
    entries[f"{DIST}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: micro-dump\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    entries[f"{DIST}/entry_points.txt"] = b"[console_scripts]\nmicro-dump = micro_dump.cli:main\n"
    rows = []
    for name, content in entries.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        rows.append((name, f"sha256={digest}", str(len(content))))
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerows(rows)
    writer.writerow((f"{DIST}/RECORD", "", ""))
    entries[f"{DIST}/RECORD"] = out.getvalue().encode()
    target = Path(wheel_directory) / filename
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return filename


def _metadata():
    return ("Metadata-Version: 2.1\nName: micro-dump\nVersion: 0.1.0\n"
            "Summary: Header-only Linux packet inspection CLI\nRequires-Python: >=3.11\n"
            "License: MIT\n\n")

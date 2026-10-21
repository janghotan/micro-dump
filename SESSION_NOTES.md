# Session Notes

## Goal

Build Micro-Dump, a Python 3.11+ Linux packet inspection CLI with a polished terminal UI, offline classic Ethernet PCAP support, safe header-only decoding, filters, tests, documentation, and a local Git commit. Use only the Python standard library; never publish or push.

## Plan

1. Inspect the target directory and applicable instructions, preserving any existing work.
2. Implement robust protocol decoding and checksum validation in isolated modules.
3. Implement classic PCAP reading, interface discovery, injectable Linux AF_PACKET capture, and clean shutdown/error handling.
4. Implement shared filtering, bounded history, interactive TUI and plain output, and CLI validation.
5. Add synthetic-frame and PCAP tests for requested protocol, malformed-input, filtering, history, and terminal behaviors.
6. Write README and packaging metadata; run the full test suite and package/build checks, fix failures, review changes, then commit locally.

## Progress

- Inspected `/home/jangho/Projects`: `micro-dump` does not exist, so there is no target content to preserve.
- Checked the Projects tree for `AGENTS.md`; only `/home/jangho/Projects/rea/AGENTS.md` exists and does not apply to the target.
- Python available: 3.14.4; Git available.
- No code implementation started yet.

## Decisions

- Runtime and tests will use only the standard library, including `unittest` rather than third-party test frameworks.
- Packet payload bytes will never be formatted, persisted, or logged; decoded summaries will retain only header-derived information and transient raw frames only as required for bounded inspection.

## Milestone updates

- Phase 1 complete: verified the target folder was absent at kickoff; created this session note before implementation. The only discovered `AGENTS.md` was outside the target scope.
- Phases 2–4 complete: added header-only protocol decoding, optional checksum checks, classic-PCAP parsing, interface listing and injectable `AF_PACKET` capture, validated composable filters, bounded packet history, terminal UI, plain output, and CLI wiring. Kept all runtime dependencies in the Python standard library.
- Phase 5 complete: added synthetic-frame and temporary-PCAP tests for VLANs, IPv4 options/fragments, IPv6 extension limits/fragments, ARP, TCP flag color treatment, UDP, ICMP/ICMPv6, malformed input, checksum status, filters, PCAP byte order/precision, bounded history, fake-screen drawing, and CLI validation. Test suite currently passes 24 tests without root or network access.
- Phase 6 verification: `python3 -m py_compile micro_dump/*.py micro_dump_build.py`, CLI help/version/interface-list smoke checks, wheel build, and installation into `/tmp/micro-dump-install` all succeeded. No global installation, live capture, publishing, or pushing performed.
- Review fixes: corrected TUI row marker rendering (previous slicing removed the marker and two characters), replaced dynamic queue imports with a normal import, removed unused imports, and made IPv6 AH extension handling explicit. Added regression coverage for FIN/SYN/RST ANSI colors, bad IPv4 checksum, ICMPv6 checksum display, and fake-screen drawing.
- Decision: initialize Git inside `micro-dump` only and commit its implementation, tests, docs, package metadata, and session notes. Ignore virtual environments, bytecode, and build outputs.

## README refresh milestone (2026-10-21)

- Resumed by reading these notes and verified the existing implementation commit is `c9d1b73` with a clean worktree before edits.
- Read `/home/jangho/.agents/skills/create-readme/SKILL.md`; rewrote `README.md` in Chinese with installation, permissions, offline PCAP, filters, TUI controls, supported formats, safety boundaries, and local verification commands.
- Added original `assets/micro-dump-logo.svg` and `assets/packet-workflow.svg`, referenced by the README using relative paths.
- Searched GitHub installed repositories and the authenticated account's searchable repository index for `micro-dump`; both searches returned no repository. An owner-list query also returned no results. No remote metadata changes were made, and no repository was created or pushed.
- Verification: all 24 unit tests passed; `py_compile`, CLI help/version smoke checks, wheel build, SVG XML parsing, README asset-link checks, and `git diff --check` passed. Wheel built as `micro_dump-0.1.0-py3-none-any.whl` in the pip cache; no global install occurred.

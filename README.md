# Micro-Dump

Micro-Dump is a Linux command-line packet inspector that decodes Ethernet and common network headers without external packet tools. It uses Python 3.11+ and the Python standard library only. Raw frames are held transiently in memory while being decoded; output includes header-derived metadata only. Packet payload bytes are never printed, saved, or logged.

## Installation

From this directory, create a project-local virtual environment and install the package:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-build-isolation .
micro-dump --help
```

The project uses a small standard-library PEP 517 wheel builder, so no third-party build backend is needed. Nothing is installed globally.

## Permissions and live capture

List interfaces without opening a capture socket:

```sh
micro-dump --list-interfaces
micro-dump --interface eth0
```

Live capture requires Linux `AF_PACKET` sockets and `CAP_NET_RAW` in the relevant network namespace. A privileged administrator can grant that capability to a dedicated Python executable with `setcap cap_net_raw+ep /path/to/python`; consider the security implications of granting capabilities to a general-purpose interpreter. Alternatively, run Micro-Dump under an account/session already authorized to open raw packet sockets. The program never invokes `sudo`, elevates privileges, or enables promiscuous mode automatically. Some systems may require additional policy configuration.

When permissions are missing, Micro-Dump reports the problem and exits. Ctrl-C and `q` stop capture; the terminal is restored on exit.

## Offline PCAP replay

Classic Ethernet PCAP files are supported in little- and big-endian microsecond and nanosecond timestamp formats. PCAP-NG and non-Ethernet link types are unsupported.

```sh
micro-dump --read capture.pcap --plain
micro-dump --read capture.pcap --count 100 --proto tcp
micro-dump --read capture.pcap --plain --no-color --check-sums
```

Offline mode does not need root privileges, open interfaces, or network access.

## Filters

Filters compose with AND semantics. Lists within a filter are alternatives:

```sh
micro-dump --interface eth0 --port 80,443
micro-dump --interface eth0 --ip 192.168.1.10
micro-dump --interface eth0 --ip 192.168.1.0/24 --ip 2001:db8::/32
micro-dump --interface eth0 --proto tcp,udp
micro-dump --interface eth0 --proto icmp,icmp6,arp --plain
```

`--port` matches either source or destination port. `--ip` matches either source or destination IPv4/IPv6 address; CIDR prefixes are accepted, and the option may be repeated. `--proto` accepts `tcp`, `udp`, `icmp`, `icmp6`, and `arp`. Invalid filters are rejected before a live capture socket is opened.

## Terminal controls and output

When stdin and stdout are terminals, the interactive UI is the default. It shows a bounded packet list and header detail for the selected packet. Use Up/Down to select, Space to pause/resume, `c` to clear the displayed history, `?` for help, and `q` to quit. Terminal resizing and narrow windows are handled by clipping rows to the available dimensions. `--no-color` disables ANSI colors; `NO_COLOR` is also respected.

Redirected output defaults to plain rows. Force that mode with `--plain`. `--count N` stops after N matching packets and `--history N` sets the maximum displayed packet history (default 500). `--check-sums` verifies IPv4 header, TCP, UDP, ICMP and ICMPv6 checksums where meaningful; checksum status can be unavailable, unchecked, or absent for protocol-defined cases.

## Decoder coverage and safety limits

The decoder handles Ethernet, up to two VLAN tags, ARP, IPv4 including options and fragments, IPv6 including extension headers and fragments, TCP, UDP, ICMP, and ICMPv6. IPv6 extension traversal is capped at 12 headers. Truncated and malformed headers are shown as decode errors rather than allowed to crash the program. When a fragment lacks a transport header, the UI shows fragment metadata instead of guessing ports.

Micro-Dump is designed for header inspection and operational troubleshooting, not payload analysis or packet injection. Do not use captures containing sensitive traffic in environments where the displayed metadata itself is sensitive.

## Tests and package check

Run standard-library tests and build a wheel locally:

```sh
python -m unittest discover -v
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
```

The tests use generated Ethernet frames and temporary PCAP files; they do not require root privileges, real interfaces, packet utilities, or external network access.

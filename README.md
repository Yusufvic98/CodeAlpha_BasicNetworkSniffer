# CodeAlpha Cyber Security Internship
## Project 1: Basic Network Sniffer

A Python-based network packet metadata sniffer developed in Kali Linux
using Scapy. This project demonstrates basic network traffic monitoring,
protocol classification, and packet metadata analysis in an authorized lab.

## Project Objectives

- Capture packets from a selected network interface.
- Identify common network protocols.
- Display source and destination addresses.
- Display TCP and UDP port information when available.
- Summarize captured packets by protocol.
- Avoid printing packet payload contents.
- Validate packet classification using automated tests.

## Features

- Configurable network interface.
- Configurable packet capture limit and timeout.
- IPv4 and IPv6 address handling.
- ARP, TCP, UDP, ICMP, and ICMPv6 classification.
- Source and destination address reporting.
- TCP/UDP port metadata.
- Capture summary with protocol counts.
- Automated regression tests using Python unittest.
- Payload non-disclosure test.

## Technology Stack

- Kali Linux
- Python 3
- Scapy
- Linux network interfaces
- Python unittest
- Git

## Project Structure

```text
CodeAlpha_BasicNetworkSniffer/
├── README.md
├── src/
│   ├── sniffer.py
│   ├── sniffer_v1.py
│   └── sniffer_v2.py
├── tests/
│   └── test_sniffer.py
└── backups/
    └── test_sniffer_v1.py
```

## Prerequisites

- Python 3
- Scapy installed in the active Python environment
- A network interface accessible to Scapy
- Appropriate permissions for packet capture

Check Python and Scapy:

```bash
python3 --version
python3 -c "import scapy; print(scapy.__version__)"
```

If Scapy is not installed, consult the Kali Linux package
documentation and install it using an appropriate supported method.

## Usage

From the project directory, run:

```bash
sudo python3 src/sniffer.py --iface eth0 --count 10 --timeout 30
```

Arguments:

| Argument | Description |
|---|---|
| `--iface` | Network interface to monitor (required) |
| `--count` | Maximum packets to capture; default 20 |
| `--timeout` | Capture timeout in seconds; default 30 |
| `-h` | Display help |

Replace `eth0` with the interface authorized for your lab.

Inspect available interfaces:

```bash
ip -br addr
```

## Automated Tests

Compile the application and test file:

```bash
python3 -m py_compile src/sniffer.py tests/test_sniffer.py
```

Run the test suite:

```bash
python3 -m unittest discover -s tests -v
```

The validated test run recorded nine passing tests covering ARP,
IPv4 ICMP, IPv4 TCP/UDP, IPv6, IPv6 TCP/UDP, ICMPv6 echo requests,
and payload non-disclosure.

Repeat the tests after any code changes.

## Lab Validation

The recorded live-capture demonstration captured ten packets:
six classified as TCP and four as UDP.

This result represents one lab capture and is not a guarantee of the
protocol distribution in other network environments.

## Limitations

- This is an educational metadata sniffer, not a full network
  detection and response platform.
- Packet capture depends on interface configuration and permissions.
- Results depend on the traffic visible to the selected interface.
- The current automated tests focus on packet classification and
  payload non-disclosure; they do not cover every possible packet type.
- Payload contents are not intentionally printed by the application.
- The tool has not been presented as a production-grade security control.

## Ethical and Authorized Use

Use this tool only on systems and networks you own or are explicitly
authorized to monitor. Follow applicable laws, organizational policies,
and privacy requirements. Avoid collecting or sharing sensitive traffic.

## Internship Evidence

Add genuine project evidence before submission, including:

- Terminal screenshot showing the automated tests passing.
- Terminal screenshot showing a live capture and protocol summary.
- Relevant source-code screenshots.
- GitHub repository link.
- A short demonstration video, if required by the internship.

## Project Status

Core packet capture, protocol classification, and automated test
validation have been demonstrated in the Kali Linux lab.

## Project Evidence

The `evidence/` folder contains original screenshots documenting the project setup, development, validation, automated tests, and live packet capture in Kali Linux.

These screenshots provide practical evidence of the implementation process and the results obtained during authorized lab testing.

[View Project Evidence](./evidence/)
Final submission readiness depends on the remaining quality checks,
documentation review, and publication of the repository.

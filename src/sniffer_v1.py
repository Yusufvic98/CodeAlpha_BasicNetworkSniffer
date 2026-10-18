#!/usr/bin/env python3

import argparse
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP


def describe_packet(packet):
    timestamp = datetime.now().astimezone().isoformat(
        timespec="milliseconds"
    )

    src = "unknown"
    dst = "unknown"
    protocol = "OTHER"
    details = ""

    if ARP in packet:
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
        protocol = "ARP"

    elif IP in packet:
        ip = packet[IP]
        src, dst = ip.src, ip.dst
        protocol = "IPv4"

        if TCP in packet:
            protocol = "TCP"
            details = (
                f" ports={packet[TCP].sport}->{packet[TCP].dport}"
            )
        elif UDP in packet:
            protocol = "UDP"
            details = (
                f" ports={packet[UDP].sport}->{packet[UDP].dport}"
            )
        elif ICMP in packet:
            protocol = "ICMP"

    elif IPv6 in packet:
        ip = packet[IPv6]
        src, dst = ip.src, ip.dst
        protocol = "IPv6"

        if TCP in packet:
            protocol = "TCP"
            details = (
                f" ports={packet[TCP].sport}->{packet[TCP].dport}"
            )
        elif UDP in packet:
            protocol = "UDP"
            details = (
                f" ports={packet[UDP].sport}->{packet[UDP].dport}"
            )
        elif ICMP in packet:
            protocol = "ICMPv6"

    print(
        f"{timestamp} | {protocol:<6} | "
        f"{src} -> {dst}{details}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Basic network packet metadata sniffer"
    )
    parser.add_argument(
        "--iface", required=True,
        help="Network interface to monitor"
    )
    parser.add_argument(
        "--count", type=int, default=20,
        help="Maximum packets to capture (default: 20)"
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="Capture timeout in seconds (default: 30)"
    )
    args = parser.parse_args()

    if args.count < 1 or args.timeout < 1:
        parser.error("--count and --timeout must be positive")

    print(f"Interface: {args.iface}")
    print(f"Maximum packets: {args.count}")
    print(f"Timeout: {args.timeout}s")
    print("Payload contents are not displayed.")
    print("Waiting for packets... Press Ctrl+C to stop.")

    try:
        sniff(
            iface=args.iface,
            prn=describe_packet,
            store=False,
            count=args.count,
            timeout=args.timeout,
        )
    except PermissionError:
        parser.error(
            "Capture permission denied. Run with sudo if authorized."
        )
    except OSError as exc:
        parser.error(f"Capture failed: {exc}")

    print("Capture finished.")


if __name__ == "__main__":
    main()

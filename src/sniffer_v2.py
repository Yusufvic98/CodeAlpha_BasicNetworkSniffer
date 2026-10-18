#!/usr/bin/env python3
"""Basic network sniffer for authorized lab traffic."""

import argparse
from collections import Counter
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, ICMPv6Unknown


def describe_packet(packet):
    timestamp = datetime.now().astimezone().isoformat(
        timespec="milliseconds"
    )

    src = dst = "unknown"
    protocol = "OTHER"
    details = ""

    if ARP in packet:
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
        protocol = "ARP"

    elif IP in packet:
        layer = packet[IP]
        src, dst = layer.src, layer.dst
        protocol = "IPv4"

        if TCP in packet:
            protocol = "TCP"
            details = f" ports={packet[TCP].sport}->{packet[TCP].dport}"
        elif UDP in packet:
            protocol = "UDP"
            details = f" ports={packet[UDP].sport}->{packet[UDP].dport}"
        elif ICMP in packet:
            protocol = "ICMP"

    elif IPv6 in packet:
        layer = packet[IPv6]
        src, dst = layer.src, layer.dst
        protocol = "IPv6"

        if TCP in packet:
            protocol = "TCP"
            details = f" ports={packet[TCP].sport}->{packet[TCP].dport}"
        elif UDP in packet:
            protocol = "UDP"
            details = f" ports={packet[UDP].sport}->{packet[UDP].dport}"
        elif ICMPv6Unknown in packet:
            protocol = "ICMPv6"

    print(f"{timestamp} | {protocol:<6} | {src} -> {dst}{details}")
    return protocol


def main():
    parser = argparse.ArgumentParser(
        description="Basic network packet metadata sniffer"
    )
    parser.add_argument("--iface", required=True, help="Interface to monitor")
    parser.add_argument("--count", type=int, default=20,
                        help="Maximum packets to capture")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Capture timeout in seconds")
    args = parser.parse_args()

    if args.count < 1 or args.timeout < 1:
        parser.error("--count and --timeout must be positive")

    totals = Counter()

    def handle_packet(packet):
        protocol = describe_packet(packet)
        totals[protocol] += 1

    print(f"Interface: {args.iface}")
    print(f"Maximum packets: {args.count}")
    print(f"Timeout: {args.timeout}s")
    print("Payload contents are not displayed.")
    print("Waiting for packets... Press Ctrl+C to stop.")

    try:
        sniff(
            iface=args.iface,
            prn=handle_packet,
            store=False,
            count=args.count,
            timeout=args.timeout,
        )
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except (PermissionError, OSError) as exc:
        parser.error(f"Capture failed: {exc}")

    print("\n--- Capture Summary ---")
    print(f"Total packets: {sum(totals.values())}")
    for name, amount in sorted(totals.items()):
        print(f"{name}: {amount}")


if __name__ == "__main__":
    main()

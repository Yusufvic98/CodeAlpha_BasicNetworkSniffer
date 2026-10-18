import sys
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from io import StringIO

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ARP
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sniffer import describe_packet


def classify(packet):
    output = StringIO()
    with redirect_stdout(output):
        return describe_packet(packet), output.getvalue()


class SnifferTests(unittest.TestCase):

    def test_icmp(self):
        result, output = classify(
            Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / ICMP()
        )
        self.assertEqual(result, "ICMP")
        self.assertIn("192.0.2.1 -> 192.0.2.2", output)

    def test_arp(self):
        result, _ = classify(
            Ether() / ARP(psrc="192.0.2.1", pdst="192.0.2.2")
        )
        self.assertEqual(result, "ARP")

    def test_tcp(self):
        result, output = classify(
            Ether() / IP(src="192.0.2.1", dst="192.0.2.2")
            / TCP(sport=12345, dport=443)
        )
        self.assertEqual(result, "TCP")
        self.assertIn("12345->443", output)

    def test_udp(self):
        result, output = classify(
            Ether() / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=53000, dport=53)
        )
        self.assertEqual(result, "UDP")
        self.assertIn("53000->53", output)

    def test_ipv6(self):
        result, output = classify(
            Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2")
        )
        self.assertEqual(result, "IPv6")
        self.assertIn("2001:db8::1 -> 2001:db8::2", output)

    def test_payload_not_printed(self):
        packet = (
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=53000, dport=53)
            / b"PRIVATE_TEST_MARKER"
        )
        _, output = classify(packet)
        self.assertNotIn("PRIVATE_TEST_MARKER", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)

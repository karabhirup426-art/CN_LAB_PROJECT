"""
test_arp.py
Automated Unit and Integration Tests for RFC 826 ARP Implementation
===================================================================
Course: CSE/PC/B/S/314 Computer Networks Laboratory
Basket 1: Address Resolution Protocol (ARP)
Author: Sk Amanullah (skaman75)

Usage:
  python -m unittest test_arp.py -v
"""

import contextlib
import io
import time
import unittest

from arp_packet import (
    BROADCAST_MAC,
    FRAME_SIZE,
    REPLY,
    REQUEST,
    ZERO_MAC,
    ArpPacket,
    EthernetFrame,
    arp_frame,
    mac_for_ip,
)
from host import Host
from switch import Switch


class TestArpPacket(unittest.TestCase):
    """Low-level packet and frame formatting tests."""

    def test_frame_size_and_fields(self):
        pkt = ArpPacket(
            opcode=REQUEST,
            sender_mac="02:00:c0:a8:01:0a",
            sender_ip="192.168.1.10",
            target_mac=ZERO_MAC,
            target_ip="192.168.1.20",
        )
        raw = arp_frame(pkt, BROADCAST_MAC)

        self.assertEqual(len(raw), FRAME_SIZE)              # Exactly 42 bytes on wire
        self.assertEqual(raw[0:6], b"\xff" * 6)             # Broadcast MAC
        self.assertEqual(raw[12:14], b"\x08\x06")           # EtherType 0x0806 (ARP)
        self.assertEqual(raw[14:16], b"\x00\x01")           # HTYPE Ethernet
        self.assertEqual(raw[16:18], b"\x08\x00")           # PTYPE IPv4
        self.assertEqual(raw[18:20], b"\x06\x04")           # HLEN 6, PLEN 4
        self.assertEqual(raw[20:22], b"\x00\x01")           # Opcode Request (1)
        self.assertEqual(raw[38:42], bytes([192, 168, 1, 20]))  # Target IP

    def test_packet_round_trip(self):
        pkt = ArpPacket(
            opcode=REPLY,
            sender_mac="02:00:c0:a8:01:14",
            sender_ip="192.168.1.20",
            target_mac="02:00:c0:a8:01:0a",
            target_ip="192.168.1.10",
        )
        raw = arp_frame(pkt, pkt.target_mac)
        frame = EthernetFrame.from_bytes(raw)
        unpacked_arp = ArpPacket.from_bytes(frame.payload)

        self.assertEqual(unpacked_arp, pkt)
        self.assertEqual(pkt.describe(), "192.168.1.20 is at 02:00:c0:a8:01:14")

    def test_gratuitous_arp(self):
        pkt = ArpPacket(
            opcode=REQUEST,
            sender_mac=mac_for_ip("192.168.1.10"),
            sender_ip="192.168.1.10",
            target_mac=ZERO_MAC,
            target_ip="192.168.1.10",
        )
        self.assertTrue(pkt.is_gratuitous)

    def test_malformed_packets_rejected(self):
        with self.assertRaises(ValueError):
            ArpPacket.from_bytes(b"\x00\x02" + b"\x00" * 26)  # Bad HTYPE
        with self.assertRaises(ValueError):
            EthernetFrame.from_bytes(b"\x00" * 10)            # Truncated frame header


class TestArpNetworkExchange(unittest.TestCase):
    """Integration tests simulating a multi-host LAN exchange over the Layer-2 switch."""

    def setUp(self):
        self.out = io.StringIO()
        self.quiet = contextlib.redirect_stdout(self.out)
        self.quiet.__enter__()

        self.switch = Switch(("127.0.0.1", 0), quiet=True).start()
        self.host_a = Host("A", "192.168.1.10", self.switch.addr, cache_ttl=1.0, timeout=0.3).start()
        self.host_b = Host("B", "192.168.1.20", self.switch.addr, cache_ttl=1.0, timeout=0.3).start()
        self.host_c = Host("C", "192.168.1.30", self.switch.addr, cache_ttl=1.0, timeout=0.3).start()
        time.sleep(0.2)

    def tearDown(self):
        for h in (self.host_a, self.host_b, self.host_c):
            h.stop()
        self.switch.stop()
        self.quiet.__exit__(None, None, None)

    def test_arp_resolution_and_passive_learning(self):
        # Host A resolves Host B
        resolved_mac = self.host_a.resolve("192.168.1.20")
        self.assertEqual(resolved_mac, mac_for_ip("192.168.1.20"))

        time.sleep(0.1)
        # RFC 826: Host B must have passively learned Host A from the request
        self.assertEqual(self.host_b.lookup("192.168.1.10"), mac_for_ip("192.168.1.10"))

        # Uninvolved Host C must not store Host A
        self.assertIsNone(self.host_c.lookup("192.168.1.10"))

        # Second query from A must result in Cache Hit
        self.host_a.resolve("192.168.1.20")
        self.assertIn("ARP Cache HIT", self.out.getvalue())

    def test_unreachable_host_timeout(self):
        mac = self.host_a.resolve("192.168.1.99")
        self.assertIsNone(mac)
        self.assertIn("UNREACHABLE", self.out.getvalue())

    def test_dynamic_cache_expiration(self):
        self.host_a.resolve("192.168.1.20")
        self.assertIsNotNone(self.host_a.lookup("192.168.1.20"))
        time.sleep(1.2)  # Wait for 1.0s TTL to expire
        self.assertIsNone(self.host_a.lookup("192.168.1.20"))

    def test_static_arp_entry_persistence(self):
        self.host_a.add_static_entry("192.168.1.200", "02:00:c0:a8:01:c8")
        time.sleep(1.2)
        # Static entry should not expire
        self.assertEqual(self.host_a.lookup("192.168.1.200"), "02:00:c0:a8:01:c8")

    def test_ipv4_data_message_delivery(self):
        ok = self.host_c.send_message("192.168.1.10", "Hello Host A")
        self.assertTrue(ok)
        time.sleep(0.2)
        self.assertEqual(self.host_a.inbox, [("192.168.1.30", "Hello Host A")])

    def test_switch_learning_table(self):
        # All 3 hosts booted and announced via switch
        self.assertEqual(len(self.switch.mac_table), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)

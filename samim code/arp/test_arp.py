"""
test_arp.py
Checks the ARP packet bytes and a full request/reply exchange.

    python -m unittest test_arp -v
"""

import contextlib
import io
import time
import unittest

from arp_packet import (BROADCAST_MAC, REPLY, REQUEST, ZERO_MAC, ArpPacket, EthernetFrame,
                        arp_frame, mac_for_ip)
from host import Host
from switch import Switch


class PacketTests(unittest.TestCase):
    def test_request_is_42_bytes_with_the_right_fields(self):
        pkt = ArpPacket(REQUEST, "02:00:c0:a8:01:0a", "192.168.1.10", ZERO_MAC, "192.168.1.20")
        raw = arp_frame(pkt, BROADCAST_MAC)
        self.assertEqual(len(raw), 42)
        self.assertEqual(raw[0:6], b"\xff" * 6)                    # broadcast destination
        self.assertEqual(raw[12:14], b"\x08\x06")                  # EtherType ARP
        self.assertEqual(raw[20:22], b"\x00\x01")                  # opcode request
        self.assertEqual(raw[38:42], bytes([192, 168, 1, 20]))     # target IP

    def test_bytes_round_trip(self):
        pkt = ArpPacket(REPLY, "02:00:c0:a8:01:14", "192.168.1.20", "02:00:c0:a8:01:0a", "192.168.1.10")
        frame = EthernetFrame.from_bytes(arp_frame(pkt, pkt.target_mac))
        self.assertEqual(ArpPacket.from_bytes(frame.payload), pkt)
        self.assertEqual(pkt.describe(), "192.168.1.20 is at 02:00:c0:a8:01:14")

    def test_bad_packet_is_rejected(self):
        with self.assertRaises(ValueError):
            ArpPacket.from_bytes(b"\x00\x02" + b"\x00" * 26)     # hardware type 2 is not Ethernet

    def test_gratuitous(self):
        self.assertTrue(ArpPacket(REQUEST, mac_for_ip("10.0.0.1"), "10.0.0.1", ZERO_MAC, "10.0.0.1").is_gratuitous)


class ExchangeTests(unittest.TestCase):
    def setUp(self):
        self.out = io.StringIO()
        self.quiet = contextlib.redirect_stdout(self.out)
        self.quiet.__enter__()
        self.switch = Switch(("127.0.0.1", 0), quiet=True).start()
        self.a = Host("A", "192.168.1.10", self.switch.addr, cache_ttl=1.0, timeout=0.3).start()
        self.b = Host("B", "192.168.1.20", self.switch.addr, cache_ttl=1.0, timeout=0.3).start()
        self.c = Host("C", "192.168.1.30", self.switch.addr, cache_ttl=1.0, timeout=0.3).start()
        time.sleep(0.2)

    def tearDown(self):
        for h in (self.a, self.b, self.c):
            h.stop()
        self.switch.stop()
        self.quiet.__exit__(None, None, None)

    def test_resolve_learn_and_cache(self):
        self.assertEqual(self.a.resolve("192.168.1.20"), mac_for_ip("192.168.1.20"))
        time.sleep(0.1)
        self.assertEqual(self.b.lookup("192.168.1.10"), mac_for_ip("192.168.1.10"))  # B learned the asker
        self.assertIsNone(self.c.lookup("192.168.1.10"))                             # C ignored it
        self.a.resolve("192.168.1.20")
        self.assertIn("ARP cache HIT", self.out.getvalue())

    def test_unknown_ip_gives_up(self):
        self.assertIsNone(self.a.resolve("192.168.1.99"))
        self.assertIn("unreachable", self.out.getvalue())

    def test_entry_expires(self):
        self.a.resolve("192.168.1.20")
        time.sleep(1.2)
        self.assertIsNone(self.a.lookup("192.168.1.20"))

    def test_message_is_delivered(self):
        self.assertTrue(self.c.send_message("192.168.1.10", "hello"))
        time.sleep(0.2)
        self.assertEqual(self.a.inbox, [("192.168.1.30", "hello")])

    def test_switch_learns_ports(self):
        self.assertEqual(len(self.switch.mac_table), 3)


if __name__ == "__main__":
    unittest.main()

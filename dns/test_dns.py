"""
test_dns.py
Checks the DNS message bytes and real queries against the server.

    python -m unittest test_dns -v
"""

import contextlib
import io
import socket
import struct
import unittest

from dns_client import lookup
from dns_message import DnsMessage, build_query, decode_name, encode_name
from dns_server import DnsServer


class MessageTests(unittest.TestCase):
    def test_name_encoding(self):
        self.assertEqual(encode_name("www.cse.myuniv.edu"), b"\x03www\x03cse\x06myuniv\x03edu\x00")
        self.assertEqual(decode_name(b"\x03www\x03cse\x06myuniv\x03edu\x00", 0), ("www.cse.myuniv.edu", 20))

    def test_compression_pointer(self):
        # "cse.myuniv.edu" at offset 0, then "www" + pointer to offset 0 (c0 00)
        msg = encode_name("cse.myuniv.edu") + b"\x03www\xc0\x00"
        self.assertEqual(decode_name(msg, 16), ("www.cse.myuniv.edu", 22))

    def test_query_bytes(self):
        raw = build_query("www.cse.myuniv.edu", "A", query_id=0x1234).to_bytes()
        self.assertEqual(raw[:12], struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0))
        self.assertEqual(raw[-4:], b"\x00\x01\x00\x01")                # type A, class IN
        self.assertEqual(DnsMessage.from_bytes(raw).questions[0].name, "www.cse.myuniv.edu")


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = DnsServer(port=0, quiet=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def ask(self, name, qtype="A"):
        with contextlib.redirect_stdout(io.StringIO()):
            reply = lookup(name, qtype, self.server.addr, timeout=1.0, retries=2)[0]
        self.assertIsNotNone(reply)
        return reply

    def test_a_record(self):
        r = self.ask("www.cse.myuniv.edu")
        self.assertEqual((r.rcode, [a.data for a in r.answers]), (0, ["192.168.151.4"]))
        self.assertTrue(r.flags & 0x0400)                                 # authoritative

    def test_cname_chain(self):
        r = self.ask("portal.cse.myuniv.edu")
        self.assertEqual([a.data for a in r.answers], ["web.cse.myuniv.edu", "www.cse.myuniv.edu", "192.168.151.4"])

    def test_mx_and_ptr(self):
        self.assertEqual(self.ask("cse.myuniv.edu", "MX").answers[0].data, (10, "mail.cse.myuniv.edu"))
        self.assertEqual(self.ask("4.151.168.192.in-addr.arpa", "PTR").answers[0].data, "www.cse.myuniv.edu")

    def test_nxdomain(self):
        r = self.ask("nothere.cse.myuniv.edu")
        self.assertEqual((r.rcode, r.answers), (3, []))

    def test_outside_zone_refused_without_forwarding(self):
        self.assertEqual(self.ask("www.google.com").rcode, 5)

    def test_reply_id_matches_query(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(build_query("ftp.cse.myuniv.edu", "A", query_id=0xBEEF).to_bytes(), self.server.addr)
        reply = DnsMessage.from_bytes(sock.recvfrom(4096)[0])
        sock.close()
        self.assertTrue(reply.is_response)
        self.assertEqual(reply.id, 0xBEEF)
        self.assertEqual(reply.answers[0].data, "192.168.151.5")


if __name__ == "__main__":
    unittest.main()

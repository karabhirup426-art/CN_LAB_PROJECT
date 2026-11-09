"""
arp_packet.py
The ARP packet (RFC 826) and the Ethernet frame that carries it, packed into
real bytes with struct, exactly as they travel on a wire.

SAMIM SEKH | Roll No. 002310501026 | CSE/PC/B/S/314 Computer Networks Lab
Group project: ARP + DNS + FTP (this file: ARP)

ETHERNET HEADER (14 bytes)               ARP PACKET (28 bytes)
  destination MAC   6                      hardware type        2   1 = Ethernet
  source MAC        6                      protocol type        2   0x0800 = IPv4
  EtherType         2   0x0806 = ARP       hardware addr length 1   6 (MAC)
                                           protocol addr length 1   4 (IPv4)
                                           opcode               2   1 = request, 2 = reply
                                           sender MAC           6
                                           sender IP            4
                                           target MAC           6   all zeros in a request
                                           target IP            4

14 + 28 = 42 bytes, the size Wireshark showed for every ARP frame in Assignment 5.
"!" in the struct formats means network byte order (big-endian).
"""

import socket
import struct
from dataclasses import dataclass

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"

ETHERTYPE_ARP = 0x0806
HTYPE_ETHERNET = 1
PTYPE_IPV4 = 0x0800
REQUEST = 1
REPLY = 2

ETH_FORMAT = "!6s6sH"                 # dst MAC, src MAC, EtherType
ARP_FORMAT = "!HHBBH6s4s6s4s"         # the 9 ARP fields listed above
ETH_HEADER_SIZE = struct.calcsize(ETH_FORMAT)   # 14
ARP_SIZE = struct.calcsize(ARP_FORMAT)          # 28


def mac_to_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))


def bytes_to_mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def mac_for_ip(ip):
    """A made-up MAC for a simulated host. The first byte 02 marks it as a
    locally administered address, the same bit Assignment 5 found on the hotspot."""
    a, b, c, d = (int(x) for x in ip.split("."))
    return f"02:00:{a:02x}:{b:02x}:{c:02x}:{d:02x}"


@dataclass
class ArpPacket:
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    def to_bytes(self):
        return struct.pack(ARP_FORMAT, HTYPE_ETHERNET, PTYPE_IPV4, 6, 4, self.opcode,
                           mac_to_bytes(self.sender_mac), socket.inet_aton(self.sender_ip),
                           mac_to_bytes(self.target_mac), socket.inet_aton(self.target_ip))

    @classmethod
    def from_bytes(cls, data):
        htype, ptype, hlen, plen, opcode, smac, sip, tmac, tip = struct.unpack(ARP_FORMAT, data[:ARP_SIZE])
        if (htype, ptype, hlen, plen) != (HTYPE_ETHERNET, PTYPE_IPV4, 6, 4):
            raise ValueError("not an Ethernet/IPv4 ARP packet")
        if opcode not in (REQUEST, REPLY):
            raise ValueError(f"unknown ARP opcode {opcode}")
        return cls(opcode, bytes_to_mac(smac), socket.inet_ntoa(sip),
                   bytes_to_mac(tmac), socket.inet_ntoa(tip))

    @property
    def is_gratuitous(self):
        """A host announcing its own address: sender IP == target IP."""
        return self.sender_ip == self.target_ip

    def describe(self):
        """Same wording as Wireshark's Info column."""
        if self.is_gratuitous:
            return f"Gratuitous ARP for {self.sender_ip} (is at {self.sender_mac})"
        if self.opcode == REQUEST:
            return f"Who has {self.target_ip}? Tell {self.sender_ip}"
        return f"{self.sender_ip} is at {self.sender_mac}"


@dataclass
class EthernetFrame:
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes

    def to_bytes(self):
        return struct.pack(ETH_FORMAT, mac_to_bytes(self.dst_mac), mac_to_bytes(self.src_mac),
                           self.ethertype) + self.payload

    @classmethod
    def from_bytes(cls, data):
        if len(data) < ETH_HEADER_SIZE:
            raise ValueError("frame shorter than an Ethernet header")
        dst, src, ethertype = struct.unpack(ETH_FORMAT, data[:ETH_HEADER_SIZE])
        return cls(bytes_to_mac(dst), bytes_to_mac(src), ethertype, data[ETH_HEADER_SIZE:])


def arp_frame(packet, dst_mac):
    """Wrap an ARP packet in an Ethernet frame and return the raw bytes."""
    return EthernetFrame(dst_mac, packet.sender_mac, ETHERTYPE_ARP, packet.to_bytes()).to_bytes()


def hex_dump(data):
    """16 bytes per line, offset + hex, like Wireshark's bytes pane."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexes = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"    {off:04x}  {hexes}")
    return "\n".join(lines)


def explain_frame(data):
    """Field-by-field breakdown of a 42-byte ARP frame, for the --hex demo."""
    eth = EthernetFrame.from_bytes(data)
    arp = ArpPacket.from_bytes(eth.payload)
    rows = [
        ("Ethernet dst MAC", data[0:6], eth.dst_mac),
        ("Ethernet src MAC", data[6:12], eth.src_mac),
        ("EtherType", data[12:14], "0x0806 = ARP"),
        ("Hardware type", data[14:16], "1 = Ethernet"),
        ("Protocol type", data[16:18], "0x0800 = IPv4"),
        ("HW / proto length", data[18:20], "6, 4"),
        ("Opcode", data[20:22], "1 = request" if arp.opcode == REQUEST else "2 = reply"),
        ("Sender MAC", data[22:28], arp.sender_mac),
        ("Sender IP", data[28:32], arp.sender_ip),
        ("Target MAC", data[32:38], arp.target_mac),
        ("Target IP", data[38:42], arp.target_ip),
    ]
    return "\n".join(f"    {name:<18} {raw.hex(' '):<18}  {meaning}" for name, raw, meaning in rows)

"""
arp_packet.py
RFC 826 ARP & RFC 903 RARP Packet and Ethernet Frame Encoder/Decoder
====================================================================
Course: CSE/PC/B/S/314 Computer Networks Laboratory
Basket 1: Address Resolution Protocol (ARP / RARP)
Author: Sk Amanullah (skaman75)

PACKET LAYOUT ON THE WIRE (42 BYTES TOTAL):
  -------------------------------------------------------------
  ETHERNET HEADER (14 bytes)
    Destination MAC : 6 bytes (FF:FF:FF:FF:FF:FF for broadcast)
    Source MAC      : 6 bytes
    EtherType       : 2 bytes (0x0806 = ARP, 0x0800 = IPv4)
  -------------------------------------------------------------
  ARP PAYLOAD (28 bytes - RFC 826 / RFC 903)
    Hardware Type   : 2 bytes (0x0001 = Ethernet)
    Protocol Type   : 2 bytes (0x0800 = IPv4)
    Hardware Length : 1 byte  (6 for MAC)
    Protocol Length : 1 byte  (4 for IPv4)
    Opcode (OPER)   : 2 bytes (1 = ARP Req, 2 = ARP Reply, 3 = RARP Req, 4 = RARP Reply)
    Sender MAC (SHA): 6 bytes
    Sender IP (SPA) : 4 bytes
    Target MAC (THA): 6 bytes (00:00:00:00:00:00 in Request)
    Target IP (TPA) : 4 bytes
  -------------------------------------------------------------
14 + 28 = 42 bytes, matching real Ethernet ARP captures in Wireshark.
"""

import socket
import struct
import sys
from dataclasses import dataclass

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ethernet & ARP Protocol Constants
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
ZERO_IP = "0.0.0.0"

ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV4 = 0x0800

HTYPE_ETHERNET = 0x0001
PTYPE_IPV4 = 0x0800

# Opcodes (RFC 826 & RFC 903)
REQUEST = 1
REPLY = 2
RARP_REQUEST = 3
RARP_REPLY = 4

OPCODE_NAMES = {
    REQUEST: "ARP Request (1)",
    REPLY: "ARP Reply (2)",
    RARP_REQUEST: "RARP Request (3)",
    RARP_REPLY: "RARP Reply (4)",
}

# Binary Struct Formats (! = Network Big-Endian)
ETH_FORMAT = "!6s6sH"                 # dst_mac (6B), src_mac (6B), ethertype (2B) = 14B
ARP_FORMAT = "!HHBBH6s4s6s4s"         # htype(2), ptype(2), hlen(1), plen(1), oper(2), sha(6), spa(4), tha(6), tpa(4) = 28B

ETH_HEADER_SIZE = struct.calcsize(ETH_FORMAT)   # 14 bytes
ARP_SIZE = struct.calcsize(ARP_FORMAT)          # 28 bytes
FRAME_SIZE = ETH_HEADER_SIZE + ARP_SIZE         # 42 bytes


def mac_to_bytes(mac_str: str) -> bytes:
    """Convert 'AA:BB:CC:DD:EE:FF' or 'aa:bb:cc:dd:ee:ff' into 6 raw bytes."""
    cleaned = mac_str.replace(":", "").replace("-", "")
    if len(cleaned) != 12:
        raise ValueError(f"Invalid MAC address string: {mac_str}")
    return bytes.fromhex(cleaned)


def bytes_to_mac(raw_bytes: bytes) -> str:
    """Convert 6 raw bytes to standard lowercase 'aa:bb:cc:dd:ee:ff' format."""
    return ":".join(f"{b:02x}" for b in raw_bytes)


def mac_for_ip(ip: str) -> str:
    """
    Generate a deterministic locally-administered MAC address for an IPv4 address.
    Prefix 02:00 denotes a locally administered unicast MAC (IEEE 802 standard).
    Example: '192.168.1.10' -> '02:00:c0:a8:01:0a'.
    """
    parts = [int(x) for x in ip.split(".")]
    if len(parts) != 4:
        raise ValueError(f"Invalid IPv4 address: {ip}")
    return f"02:00:{parts[0]:02x}:{parts[1]:02x}:{parts[2]:02x}:{parts[3]:02x}"


@dataclass
class ArpPacket:
    """28-byte RFC 826 ARP / RFC 903 RARP Packet."""
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    htype: int = HTYPE_ETHERNET
    ptype: int = PTYPE_IPV4
    hlen: int = 6
    plen: int = 4

    def to_bytes(self) -> bytes:
        """Serialize into 28 raw wire bytes."""
        return struct.pack(
            ARP_FORMAT,
            self.htype,
            self.ptype,
            self.hlen,
            self.plen,
            self.opcode,
            mac_to_bytes(self.sender_mac),
            socket.inet_aton(self.sender_ip),
            mac_to_bytes(self.target_mac),
            socket.inet_aton(self.target_ip),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "ArpPacket":
        """Deserialize from raw bytes."""
        if len(data) < ARP_SIZE:
            raise ValueError(f"Packet too short for ARP: {len(data)} bytes (expected {ARP_SIZE})")
        htype, ptype, hlen, plen, opcode, smac, sip, tmac, tip = struct.unpack(
            ARP_FORMAT, data[:ARP_SIZE]
        )
        if (htype, ptype, hlen, plen) != (HTYPE_ETHERNET, PTYPE_IPV4, 6, 4):
            raise ValueError(f"Unsupported ARP hardware/proto type: htype={htype}, ptype={ptype}")
        if opcode not in OPCODE_NAMES:
            raise ValueError(f"Unknown or unsupported ARP opcode: {opcode}")

        return cls(
            opcode=opcode,
            sender_mac=bytes_to_mac(smac),
            sender_ip=socket.inet_ntoa(sip),
            target_mac=bytes_to_mac(tmac),
            target_ip=socket.inet_ntoa(tip),
            htype=htype,
            ptype=ptype,
            hlen=hlen,
            plen=plen,
        )

    @property
    def is_gratuitous(self) -> bool:
        """True if Gratuitous ARP: host announcing its own IP (sender IP == target IP)."""
        return self.sender_ip == self.target_ip and self.sender_ip != ZERO_IP

    def describe(self) -> str:
        """Wireshark Info column description."""
        if self.is_gratuitous:
            return f"Gratuitous ARP for {self.sender_ip} (is at {self.sender_mac})"
        if self.opcode == REQUEST:
            return f"Who has {self.target_ip}? Tell {self.sender_ip}"
        elif self.opcode == REPLY:
            return f"{self.sender_ip} is at {self.sender_mac}"
        elif self.opcode == RARP_REQUEST:
            return f"Who is {self.target_mac}? Tell {self.sender_mac}"
        elif self.opcode == RARP_REPLY:
            return f"{self.target_mac} is at {self.target_ip}"
        return f"ARP opcode {self.opcode}"


@dataclass
class EthernetFrame:
    """14-byte Ethernet II Frame Header with payload."""
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes

    def to_bytes(self) -> bytes:
        """Serialize 14B Ethernet header + payload."""
        return struct.pack(
            ETH_FORMAT,
            mac_to_bytes(self.dst_mac),
            mac_to_bytes(self.src_mac),
            self.ethertype,
        ) + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "EthernetFrame":
        if len(data) < ETH_HEADER_SIZE:
            raise ValueError(f"Frame shorter than Ethernet header ({len(data)} bytes)")
        dst, src, ethertype = struct.unpack(ETH_FORMAT, data[:ETH_HEADER_SIZE])
        return cls(
            dst_mac=bytes_to_mac(dst),
            src_mac=bytes_to_mac(src),
            ethertype=ethertype,
            payload=data[ETH_HEADER_SIZE:],
        )


def arp_frame(packet: ArpPacket, dst_mac: str) -> bytes:
    """Encapsulate an ARP packet into an Ethernet frame (42 bytes)."""
    frame = EthernetFrame(
        dst_mac=dst_mac,
        src_mac=packet.sender_mac,
        ethertype=ETHERTYPE_ARP,
        payload=packet.to_bytes(),
    )
    return frame.to_bytes()


def hex_dump(data: bytes) -> str:
    """Format raw bytes as 16 bytes per line with hex offset, matching Wireshark bytes pane."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        hexes = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"    {off:04x}  {hexes}")
    return "\n".join(lines)


def explain_frame(data: bytes) -> str:
    """Field-by-field breakdown of the 42-byte Ethernet+ARP frame for detailed lab inspection."""
    eth = EthernetFrame.from_bytes(data)
    arp = ArpPacket.from_bytes(eth.payload)
    opcode_meaning = OPCODE_NAMES.get(arp.opcode, f"Opcode {arp.opcode}")

    rows = [
        ("Ethernet dst MAC", data[0:6], eth.dst_mac),
        ("Ethernet src MAC", data[6:12], eth.src_mac),
        ("EtherType", data[12:14], "0x0806 (ARP)"),
        ("Hardware type", data[14:16], "1 (Ethernet)"),
        ("Protocol type", data[16:18], "0x0800 (IPv4)"),
        ("HW / Proto length", data[18:20], "6 bytes MAC, 4 bytes IPv4"),
        ("Opcode (OPER)", data[20:22], opcode_meaning),
        ("Sender MAC (SHA)", data[22:28], arp.sender_mac),
        ("Sender IP  (SPA)", data[28:32], arp.sender_ip),
        ("Target MAC (THA)", data[32:38], arp.target_mac),
        ("Target IP  (TPA)", data[38:42], arp.target_ip),
    ]
    return "\n".join(f"    {name:<18} {raw.hex(' '):<18}  {meaning}" for name, raw, meaning in rows)

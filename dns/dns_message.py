"""
dns_message.py
Builds and reads real DNS messages (RFC 1035) as bytes. The same bytes work
with Windows nslookup, Wireshark and public servers such as 8.8.8.8.

SAMIM SEKH | Roll No. 002310501026 | CSE/PC/B/S/314 Computer Networks Lab
Group project: ARP + DNS + FTP (this file: DNS)

A DNS MESSAGE
  +---------------------+
  | Header   (12 bytes) |  ID, flags, and how many entries each section has
  | Question            |  the name and type asked for
  | Answer              |  resource records (RRs) that answer it
  | Authority           |  RRs naming the servers in charge (not used here)
  | Additional          |  extra RRs (not used here)
  +---------------------+

HEADER                                    FLAGS (16 bits)
  ID        2  matches reply to query       QR      1 bit   0 query, 1 response
  flags     2  see right                    Opcode  4 bits  0 = standard query
  QDCOUNT   2  questions                    AA      1 bit   authoritative answer
  ANCOUNT   2  answers                      TC      1 bit   truncated
  NSCOUNT   2  authority records            RD      1 bit   recursion desired
  ARCOUNT   2  additional records           RA      1 bit   recursion available
                                            Z       3 bits  zero
                                            RCODE   4 bits  0 OK, 3 NXDOMAIN ...

NAMES are written as labels: www.cse.myuniv.edu ->
  03 'www' 03 'cse' 06 'myuniv' 03 'edu' 00
A reply may shorten a repeated name with a 2-byte POINTER (first two bits 11)
that says "the rest of this name is at offset N". We read pointers (real
servers use them) but always write full names, which is also valid.

RESOURCE RECORD:  name | type 2 | class 2 | TTL 4 | RDLENGTH 2 | RDATA
"""

import random
import socket
import struct
from dataclasses import dataclass, field

TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 28: "AAAA"}
TYPE_NUMBERS = {v: k for k, v in TYPES.items()}
CLASS_IN = 1
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

HEADER_FORMAT = "!HHHHHH"


def type_name(t):
    return TYPES.get(t, f"TYPE{t}")


# ---------------- names ----------------
def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            raw = label.encode("ascii")
            if len(raw) > 63:
                raise ValueError(f"label too long: {label}")
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def decode_name(msg, offset):
    """Read a name starting at offset. Returns (name, offset just after it)."""
    labels = []
    end = None                                # where the name ends in the original place
    jumps = 0
    while True:
        length = msg[offset]
        if length & 0xC0 == 0xC0:             # pointer: 11xxxxxx xxxxxxxx
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | msg[offset + 1]
            jumps += 1
            if jumps > 20:
                raise ValueError("name pointer loop")
            continue
        if length == 0:
            offset += 1
            break
        labels.append(msg[offset + 1:offset + 1 + length].decode("ascii"))
        offset += 1 + length
    return ".".join(labels), (end if end is not None else offset)


# ---------------- sections ----------------
@dataclass
class Question:
    name: str
    qtype: int = 1
    qclass: int = CLASS_IN

    def to_bytes(self):
        return encode_name(self.name) + struct.pack("!HH", self.qtype, self.qclass)


@dataclass
class ResourceRecord:
    name: str
    rtype: int
    ttl: int
    data: object        # A/AAAA: "1.2.3.4" ; CNAME/NS/PTR: "host.name" ; MX: (preference, "host.name")
    rclass: int = CLASS_IN

    def rdata_bytes(self):
        if self.rtype == 1:
            return socket.inet_aton(self.data)
        if self.rtype == 28:
            return socket.inet_pton(socket.AF_INET6, self.data)
        if self.rtype in (2, 5, 12):
            return encode_name(self.data)
        if self.rtype == 15:
            pref, host = self.data
            return struct.pack("!H", pref) + encode_name(host)
        raise ValueError(f"cannot encode type {self.rtype}")

    def to_bytes(self):
        rdata = self.rdata_bytes()
        return encode_name(self.name) + struct.pack("!HHIH", self.rtype, self.rclass, self.ttl, len(rdata)) + rdata

    def value_text(self):
        if self.rtype == 15:
            return f"{self.data[0]} {self.data[1]}"
        return str(self.data)

    def __str__(self):
        return f"{self.name:<26} {self.ttl:>6}  {type_name(self.rtype):<5}  {self.value_text()}"


def read_record(msg, offset):
    name, offset = decode_name(msg, offset)
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[offset:offset + 10])
    offset += 10
    raw = msg[offset:offset + rdlen]
    if rtype == 1:
        data = socket.inet_ntoa(raw)
    elif rtype == 28:
        data = socket.inet_ntop(socket.AF_INET6, raw)
    elif rtype in (2, 5, 12):
        data = decode_name(msg, offset)[0]
    elif rtype == 15:
        data = (struct.unpack("!H", raw[:2])[0], decode_name(msg, offset + 2)[0])
    else:
        data = raw.hex()
    return ResourceRecord(name, rtype, ttl, data, rclass), offset + rdlen


# ---------------- the whole message ----------------
@dataclass
class DnsMessage:
    id: int
    flags: int
    questions: list = field(default_factory=list)
    answers: list = field(default_factory=list)
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)

    # flag helpers
    @property
    def is_response(self):
        return bool(self.flags & 0x8000)

    @property
    def rcode(self):
        return self.flags & 0x000F

    def flag_text(self):
        names = [("qr", 0x8000), ("aa", 0x0400), ("tc", 0x0200), ("rd", 0x0100), ("ra", 0x0080)]
        return " ".join(n for n, bit in names if self.flags & bit) or "-"

    def to_bytes(self):
        out = struct.pack(HEADER_FORMAT, self.id, self.flags, len(self.questions), len(self.answers),
                          len(self.authority), len(self.additional))
        for q in self.questions:
            out += q.to_bytes()
        for rr in self.answers + self.authority + self.additional:
            out += rr.to_bytes()
        return out

    @classmethod
    def from_bytes(cls, msg):
        if len(msg) < 12:
            raise ValueError("message shorter than a DNS header")
        mid, flags, qd, an, ns, ar = struct.unpack(HEADER_FORMAT, msg[:12])
        offset = 12
        questions = []
        for _ in range(qd):
            name, offset = decode_name(msg, offset)
            qtype, qclass = struct.unpack("!HH", msg[offset:offset + 4])
            offset += 4
            questions.append(Question(name, qtype, qclass))
        sections = []
        for count in (an, ns, ar):
            records = []
            for _ in range(count):
                rr, offset = read_record(msg, offset)
                records.append(rr)
            sections.append(records)
        return cls(mid, flags, questions, *sections)


def build_query(name, qtype="A", recursion=True, query_id=None):
    """qtype is a name such as "MX" or a type number such as 15."""
    if isinstance(qtype, str):
        qtype = TYPE_NUMBERS[qtype.upper()]
    flags = 0x0100 if recursion else 0x0000             # RD bit
    qid = query_id if query_id is not None else random.randint(0, 0xFFFF)
    return DnsMessage(qid, flags, [Question(name, qtype)])


def response_flags(query, rcode=0, authoritative=False, recursion_available=False):
    flags = 0x8000 | (query.flags & 0x0100) | rcode     # QR=1, copy RD from the query
    if authoritative:
        flags |= 0x0400
    if recursion_available:
        flags |= 0x0080
    return flags


def hex_dump(data):
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexes = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {off:04x}  {hexes:<47}  {text}")
    return "\n".join(lines)

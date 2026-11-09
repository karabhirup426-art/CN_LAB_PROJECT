# Computer Networks Group Project: ARP and DNS

SAMIM SEKH | Roll No. 002310501026 | CSE/PC/B/S/314 Computer Networks Lab, Jadavpur University

The group implements one protocol from each basket: **ARP** (basket 1), **DNS** (basket 2) and **FTP** (basket 3).
This folder holds the **ARP** and **DNS** parts, in plain Python 3 with only the standard library.

Both parts build the **real packet formats byte by byte** with `struct` and send them over **UDP sockets**:

| Part | Packet format | Transport | Why |
|---|---|---|---|
| ARP | 14-byte Ethernet header + 28-byte ARP packet = 42 bytes (RFC 826) | UDP to a simulated switch | Real ARP needs raw sockets and admin rights; each host's UDP address plays one switch port |
| DNS | 12-byte header + question + resource records (RFC 1035) | UDP port 53 | A lookup is one small question and one small answer; no connection needed |

## Folder layout

```
arp/
  arp_packet.py   ARP packet + Ethernet frame <-> bytes, hex dump
  switch.py       learning switch: learns source MACs, floods broadcasts, forwards unicasts
  host.py         a host: ARP cache with expiry, request/reply, retries, gratuitous ARP
  demo.py         the whole story in one command
  test_arp.py     unit tests
dns/
  dns_message.py  DNS message <-> bytes (names, compression pointers, A NS CNAME PTR MX AAAA)
  zone.txt        records of cse.myuniv.edu
  dns_server.py   authoritative server, CNAME chains, NXDOMAIN, PTR, forwarding + cache
  dns_client.py   a small nslookup with retries and hex dump
  demo.py         the whole story in one command
  test_dns.py     unit tests
HOW_TO_SHOW.md    demo order for the lab, and viva answers
```

## Quick start

```
cd arp
python demo.py
```

```
cd dns
python demo.py
```

See [HOW_TO_SHOW.md](HOW_TO_SHOW.md) for the live, multi-terminal version.

## Tests

```
cd arp && python -m unittest test_arp -v
cd dns && python -m unittest test_dns -v
```

Tested on Windows 11 with Python 3.14. Python 3.9 or newer should work.

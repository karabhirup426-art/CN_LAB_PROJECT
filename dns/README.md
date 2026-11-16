# Basket 2: Domain Name System (DNS)

**Course:** CSE/PC/B/S/314 Computer Networks Laboratory  
**Basket 2 Implementation:** Application-layer protocol over UDP  
**Author:** Samim Sekh (ssk224-git)  

---

## 1. Overview & RFC Standard

This module implements the **Domain Name System (RFC 1035)** in plain Python 3 using only the standard library (`socket`, `struct`, `threading`). Every message is built and read **byte by byte**, so the same packets work with Windows `nslookup`, Wireshark and public servers such as `8.8.8.8`.

### The Networking Problem DNS Solves
People and programs use names (e.g. `ftp.cse.myuniv.edu`), but an IP packet needs a 32-bit address (e.g. `192.168.151.5`). **DNS maps a name to its address**, and also answers related questions: which host takes the mail (MX), which server is in charge of the zone (NS), and which name belongs to an address (PTR).

### Why UDP
A lookup is one small question and one small answer, so setting up a TCP connection would cost more than the lookup itself. DNS uses **UDP port 53**. UDP gives no delivery guarantee, so the client waits for a timeout and asks again.

### On-Wire Message Format
```text
+---------------------+
| Header   (12 bytes) |  ID, flags, and how many entries each section has
| Question            |  the name and type asked for
| Answer              |  resource records (RRs) that answer it
| Authority           |  RRs naming the servers in charge
| Additional          |  extra RRs
+---------------------+

HEADER (6 fields x 2 bytes)               FLAGS (16 bits)
  ID        matches reply to query          QR      1 bit   0 query, 1 response
  flags     see right                       Opcode  4 bits  0 = standard query
  QDCOUNT   questions                       AA      1 bit   authoritative answer
  ANCOUNT   answers                         TC      1 bit   truncated
  NSCOUNT   authority records               RD      1 bit   recursion desired
  ARCOUNT   additional records              RA      1 bit   recursion available
                                            Z       3 bits  zero
                                            RCODE   4 bits  0 NOERROR, 3 NXDOMAIN, 5 REFUSED

NAME as labels:   www.cse.myuniv.edu  ->  03 'www' 03 'cse' 06 'myuniv' 03 'edu' 00
RESOURCE RECORD:  name | type 2 | class 2 | TTL 4 | RDLENGTH 2 | RDATA
```

---

## 2. Architecture & Components

```text
dns/
├── dns_message.py      # DNS message <-> bytes: header, labels, compression pointers, hex dump
├── dns_server.py       # Authoritative server for cse.myuniv.edu + forwarding resolver with a TTL cache
├── dns_client.py       # Small nslookup: timeout, retries, hex dump, interactive mode
├── zone.txt            # Records of the zone cse.myuniv.edu
├── demo.py             # 7-step automated laboratory demonstration script
├── test_dns.py         # Unit and integration test suite (9 test cases)
├── HOW_TO_SHOW_DNS.md  # Multi-terminal lab demonstration guide & viva Q&A
└── README.md           # Module documentation
```

### Key Protocol Mechanisms Implemented:
1. **Binary message codec (`dns_message.py`):**
   * Packs and unpacks the 12-byte header with `struct`, and names as length-prefixed labels.
   * Reads **compression pointers** (2 bytes starting with bits `11`), which real servers use; always writes full names, which is also valid.
   * Record types: `A`, `NS`, `CNAME`, `PTR`, `MX`, `AAAA`.
2. **Authoritative answers (`dns_server.py` + `zone.txt`):**
   * Names inside `cse.myuniv.edu` are answered from the zone file with the **AA** flag set.
   * **CNAME chains** are followed (`portal` -> `web` -> `www` -> address) and every step is returned.
   * **NXDOMAIN** (rcode 3) when the name does not exist; **NOERROR with no answers** when the name exists but has no record of that type.
   * **PTR records** for reverse lookup are built automatically from every `A` record.
3. **Forwarding and caching (`--forward`):**
   * A name outside the zone is sent to an upstream server (default `8.8.8.8`) and the answer is cached for its TTL.
   * A second query is answered from the cache with the TTL counted down, without the AA flag (non-authoritative) and with **RA** set.
   * Without `--forward`, outside names get **REFUSED** (rcode 5).
4. **Client reliability (`dns_client.py`):**
   * Waits `--timeout` seconds and re-sends the same query up to `--retries` times.
   * Accepts a reply only when its **ID** matches the query.

---

## 3. Quick Start & Testing

### Run Automated Unit Tests (9 Tests)
```bash
python -m unittest test_dns.py -v
```

### Run Step-by-Step Demonstration
```bash
python demo.py
```
* Add `--offline` to skip the forwarding step when there is no internet.
* Add `--step` to pause and press Enter between each demonstration step.

---

## 4. Live Multi-Terminal Laboratory Run

Open two terminal windows inside `dns/`:

**Terminal 1 (DNS Server):**
```bash
python dns_server.py --forward
```
If port 53 is busy, add `--port 5300` and use `-p 5300` in the client.

**Terminal 2 (DNS Client):**
```bash
python dns_client.py www.cse.myuniv.edu --hex           # A record, with the bytes
python dns_client.py portal.cse.myuniv.edu              # CNAME chain
python dns_client.py cse.myuniv.edu -t MX               # Mail server
python dns_client.py 5.151.168.192.in-addr.arpa -t PTR  # Reverse lookup
python dns_client.py nothere.cse.myuniv.edu             # NXDOMAIN
python dns_client.py www.google.com                     # Forwarded, then cached
```

**Terminal 2 (Windows `nslookup`, proves the bytes follow the standard):**
```bash
nslookup www.cse.myuniv.edu 127.0.0.1
nslookup -type=mx cse.myuniv.edu 127.0.0.1
nslookup 192.168.151.5 127.0.0.1
```

See [HOW_TO_SHOW_DNS.md](HOW_TO_SHOW_DNS.md) for what to point out at each step and the viva questions.

Tested on Windows 11 with Python 3.14. Python 3.9 or newer should work.

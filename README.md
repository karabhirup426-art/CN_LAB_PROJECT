# Computer Networks Lab - Group Project

**Course:** CSE/PC/B/S/314 Computer Networks Laboratory  
**Requirement:** Implement one protocol from each basket using TCP/UDP sockets in Python.

| Basket | Protocol Chosen | Layer | Implementation | Transport Protocol |
|---|---|---|---|---|
| **Basket 1** | **ARP** (Address Resolution Protocol) | Data Link / Network | `arp/` | UDP (simulated Ethernet switch, RFC 826) |
| **Basket 2** | **DNS** (Domain Name System) | Transport / Infrastructure | `samim code/dns/` | UDP port 53 (RFC 1035) |
| **Basket 3** | **FTP** (File Transfer Protocol) | Application Layer | `ftp/` | TCP port 2121 (RFC 959) |

---

## The End-to-End Group Story (Connecting ARP, DNS & FTP)

1. **Step 1 (DNS - Basket 2):** A client resolves `ftp.cse.myuniv.edu` using our authoritative DNS server (`dns_server.py`), which loads `zone.txt` and returns IP `192.168.151.5`.
2. **Step 2 (ARP - Basket 1):** To send IP packets to `192.168.151.5` over the LAN, the host uses ARP (`host.py`, `switch.py`) to broadcast and map the target IP to its physical MAC address.
3. **Step 3 (FTP - Basket 3):** With IP and MAC resolved, the client opens a TCP connection on port 2121 to our FTP server (`ftp_server.py`), authenticates, requests passive mode data connections (`PASV`), and reliably transfers files with full MD5 data integrity.

---

## Quick Start & Demonstrations

### 1. ARP Demonstration
```bash
cd arp
python demo.py --hex
```

### 2. DNS Demonstration
```bash
cd "samim code/dns"
python demo.py
```

### 3. FTP Demonstration
```bash
cd ftp
python demo.py
```
*(Add `--step` to pause and press Enter between steps).*

---

## Running Unit Tests
```bash
cd arp && python -m unittest test_arp -v
cd "samim code/dns" && python -m unittest test_dns -v
cd ftp && python -m unittest test_ftp -v
```

See [`arp/HOW_TO_SHOW_ARP.md`](arp/HOW_TO_SHOW_ARP.md), [`samim code/HOW_TO_SHOW.md`](samim%20code/HOW_TO_SHOW.md) and [`ftp/HOW_TO_SHOW_FTP.md`](ftp/HOW_TO_SHOW_FTP.md) for detailed multi-terminal live demonstration scripts and viva examination questions.

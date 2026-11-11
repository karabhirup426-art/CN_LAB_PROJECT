# Basket 1: Address Resolution Protocol (ARP / RARP)

**Course:** CSE/PC/B/S/314 Computer Networks Laboratory  
**Basket 1 Implementation:** Layer-2 / Network Layer Protocol  
**Author:** Sk Amanullah (skaman75)  

---

## 1. Overview & RFC Standards

This module implements the **Address Resolution Protocol (RFC 826)** and **Reverse Address Resolution Protocol (RFC 903)** in pure Python using only standard socket libraries (`socket`, `struct`, `threading`).

### The Networking Problem ARP Solves
Applications and network software operate with 32-bit logical IPv4 addresses (e.g. `192.168.1.50`). However, standard Network Interface Cards (NICs) transmit data across physical transmission media using 48-bit physical MAC addresses (e.g. `02:00:c0:a8:01:32`). **ARP bridges Layer 3 (IPv4) to Layer 2 (Ethernet).**

### 42-Byte On-Wire Packet Architecture
Real ARP frames traveling on an Ethernet segment consist of a 14-byte Ethernet II header encapsulating a 28-byte ARP payload:

```text
+--------------------------------------------------------------------------+
|                     ETHERNET II HEADER (14 Bytes)                        |
|  Destination MAC (6B)  |  Source MAC (6B)  |  EtherType (2B = 0x0806)    |
+--------------------------------------------------------------------------+
|                     RFC 826 ARP PAYLOAD (28 Bytes)                       |
|  Hardware Type (2B)    |  Protocol Type (2B) | HLEN (1B=6) | PLEN (1B=4) |
|  Opcode (2B: 1=Req, 2=Reply, 3=RARP Req, 4=RARP Reply)                  |
|  Sender Hardware Addr (SHA: 6B MAC)                                      |
|  Sender Protocol Addr (SPA: 4B IPv4)                                     |
|  Target Hardware Addr (THA: 6B MAC)                                      |
|  Target Protocol Addr (TPA: 4B IPv4)                                     |
+--------------------------------------------------------------------------+
14 + 28 = 42 bytes (matches exact capture length in Wireshark)
```

---

## 2. Architecture & Components

```text
arp/
├── arp_packet.py       # 14B Ethernet + 28B ARP packet encoder/decoder & hex inspector
├── switch.py           # Layer-2 IEEE 802.1D Learning Switch over UDP
├── host.py             # LAN Host with local ARP Cache, TTL, Static entries & data encapsulation
├── demo.py             # 9-step automated laboratory demonstration script
├── test_arp.py         # Automated unit and integration test suite (10 test cases)
├── HOW_TO_SHOW_ARP.md  # Multi-terminal lab demonstration guide & viva Q&A
└── README.md           # Module documentation
```

### Key Protocol Mechanisms Implemented:
1. **Layer-2 Learning Switch (`switch.py`):**
   * Dynamically learns `Source MAC -> Ingress Port` mappings.
   * Floods broadcasts (`ff:ff:ff:ff:ff:ff`) to all ports except incoming port.
   * Unicast forwarding directly to destination port when MAC is known.
2. **Local ARP Cache Table (`host.py`):**
   * **Cache Hit vs Cache Miss:** If IP is cached and valid, MAC is returned instantly with zero network packets.
   * **TTL Expiration:** Configurable cache lifetime (default 60s); stale entries are evicted.
   * **Static Entries (`arp -s`):** Permanent entries that never expire.
   * **Manual Eviction (`arp -d`):** Removal of specific IP mappings.
3. **Passive Asker Learning (RFC 826):**
   * When Host B receives an ARP Request from Host A, Host B immediately caches Host A's MAC. Host B can then reply or send future traffic without issuing an ARP query.
4. **Gratuitous ARP & Conflict Detection:**
   * Broadcast on host startup to announce IP/MAC mapping and immediately detect if another host claims the same IP.
5. **Data Encapsulation Demonstration (`send <ip> <msg>`):**
   * Higher-layer IPv4 data packets (`EtherType 0x0800`) cannot be transmitted until the destination MAC is resolved.

---

## 3. Quick Start & Testing

### Run Automated Unit Tests (10 Tests)
```bash
python -m unittest test_arp.py -v
```

### Run Step-by-Step Demonstration
```bash
python demo.py
```
* Add `--hex` to inspect the 42-byte binary wire frames field-by-field.
* Add `--step` to pause and press Enter between each demonstration step.

---

## 4. Live Multi-Terminal Laboratory Run

Open separate terminal windows inside `arp/`:

**Terminal 1 (Switch):**
```bash
python switch.py
```

**Terminal 2 (Host A):**
```bash
python host.py --name A --ip 192.168.1.10
```

**Terminal 3 (Host B):**
```bash
python host.py --name B --ip 192.168.1.20
```

**Terminal 4 (Host C - Optional):**
```bash
python host.py --name C --ip 192.168.1.30
```

Inside Host A's shell, execute:
```text
A> arp 192.168.1.20              # First query: Cache Miss -> Broadcast -> Learned
A> arp 192.168.1.20              # Second query: Instant Cache Hit (0 packets)
A> send 192.168.1.20 Hello B     # Sends IPv4 data to B using resolved MAC
A> table                         # Display local ARP cache table (or: arp -a)
A> add 192.168.1.200 02:00:00:01 # Add static permanent ARP entry (arp -s)
A> del 192.168.1.200             # Delete ARP entry (arp -d)
A> arp 192.168.1.99              # Query non-existent IP: 3 retries, then unreachable
```

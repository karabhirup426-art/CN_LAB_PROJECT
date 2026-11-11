# Basket 1: How to Demonstrate ARP in the Lab & Viva Guide

**Course:** CSE/PC/B/S/314 Computer Networks Laboratory  
**Basket 1:** Address Resolution Protocol (ARP / RARP)  
**Author:** Sk Amanullah (skaman75)  

---

## 1. Fast Automated Demo (15 Seconds)

For a quick, polished presentation in front of the lab instructor:

```bash
cd arp
python demo.py --hex
```
*(Add `--step` to pause and press Enter between each demonstration step).*

### What to highlight during each step:
1. **Step 1 (Gratuitous ARP):** Every host announces its IP upon connecting to the LAN. Uninvolved hosts ignore it unless already cached.
2. **Step 2 (Cache Miss & Broadcast):** Host A knows Host B's IP, but not its physical MAC. The switch **floods** the broadcast request (`ff:ff:ff:ff:ff:ff`) to all ports. Host C sees target IP is not its own and drops the frame. Host B sends a **unicast reply** directly back to Host A's port. The `--hex` flag displays the 42-byte binary layout (`0x0806` EtherType, `0x0001` Request, `0x0002` Reply).
3. **Step 3 (Cache Hit):** Host A queries Host B again. The MAC is retrieved immediately from Host A's local cache with **0 packets sent across the wire**.
4. **Step 4 (Passive Asker Learning):** RFC 826 specifies that when Host B receives the request from Host A, Host B stores Host A's MAC immediately. Host B can therefore transmit data back to Host A without issuing an ARP query!
5. **Step 5 (Data Encapsulation Requires ARP):** Host C attempts to send an IPv4 packet to Host A. It automatically performs an on-demand ARP resolution before framing the packet.
6. **Step 6 (Static Permanent Entries):** Demonstrates `arp -s` functionality. Static entries have infinite lifetime and are never purged by TTL eviction.
7. **Step 7 (Unreachable Host & Retries):** When querying an inactive IP (`192.168.1.99`), the host re-transmits 3 times before declaring `Destination Unreachable`.
8. **Step 8 (TTL Expiry):** Dynamic cache entries expire when the TTL countdown reaches 0, forcing a fresh resolution to detect network changes.
9. **Step 9 (Switch MAC Table):** The Layer-2 switch displays its learned MAC address table mapping each MAC to its ingress port.

---

## 2. Interactive Multi-Terminal Demo

Open separate terminal windows inside `arp/`:

### Terminal 1: Start the Switch
```bash
python switch.py
```

### Terminal 2: Start Host A
```bash
python host.py --name A --ip 192.168.1.10
```

### Terminal 3: Start Host B
```bash
python host.py --name B --ip 192.168.1.20
```

### Commands to Run Inside Host A:
```text
A> arp 192.168.1.20
A> arp 192.168.1.20
A> send 192.168.1.20 Hello B
A> table
A> add 192.168.1.254 02:00:c0:a8:01:fe
A> table
A> del 192.168.1.254
A> arp 192.168.1.99
```

### IP Address Conflict Demo:
In a 4th terminal, launch a duplicate host claiming Host B's IP:
```bash
python host.py --name Rogue --ip 192.168.1.20 --mac 02:00:de:ad:be:ef
```
Host B immediately detects the collision via Gratuitous ARP and prints:
`!! [CRITICAL] IP ADDRESS CONFLICT DETECTED: 02:00:de:ad:be:ef is also claiming our IP 192.168.1.20!`

---

## 3. High-Probability Lab Viva Questions & Model Answers

### Q1: At which OSI layer does ARP operate?
> **Answer:** ARP operates between **Layer 2 (Data Link Layer)** and **Layer 3 (Network Layer)**. It encapsulates directly into Layer-2 Ethernet frames (`EtherType = 0x0806`), without an IP or UDP/TCP header, but its purpose is to serve Layer-3 IPv4 address resolution.

### Q2: Why is the ARP Request broadcast, but the ARP Reply unicast?
> **Answer:** The requester does not know who owns the target IP or what their MAC address is, so the request must be broadcast (`ff:ff:ff:ff:ff:ff`) to reach all hosts in the local broadcast domain. However, the responder extracts the sender's MAC from the request payload and sends the reply unicast directly to the requester.

### Q3: What is the size of an Ethernet ARP frame?
> **Answer:** Exactly **42 bytes** (or 64 bytes on a real wire with 4-byte CRC and 18-byte minimum Ethernet padding). The Ethernet II header is 14 bytes (`6B dst + 6B src + 2B EtherType`), and the RFC 826 ARP payload is 28 bytes (`2B HTYPE + 2B PTYPE + 1B HLEN + 1B PLEN + 2B OPER + 6B SHA + 4B SPA + 6B THA + 4B TPA`).

### Q4: What is Asker Learning in RFC 826?
> **Answer:** When Host B receives an ARP request from Host A, Host B records Host A's mapping (`SPA -> SHA`) in its own ARP cache before replying. This optimizes network traffic because when Host B replies or sends return traffic to Host A, Host B does not need to send an ARP request.

### Q5: What is Gratuitous ARP and what are its two main purposes?
> **Answer:** A Gratuitous ARP is an ARP packet where the Sender Protocol Address (SPA) equals the Target Protocol Address (TPA). Its purposes:
> 1. **Duplicate Address Detection (DAD):** To detect IP address conflicts upon joining the LAN.
> 2. **Updating Peer Caches / Switch MAC Tables:** To notify switch and peer nodes when a NIC or MAC address changes (e.g. during failover or clustering).

### Q6: What is the difference between ARP and RARP?
> **Answer:** ARP resolves a logical IP address to a physical MAC address (Opcodes 1 and 2). **Reverse ARP (RARP, RFC 903)** resolves a physical MAC address to an IP address (Opcodes 3 and 4), traditionally used by diskless workstations during boot to discover their assigned IP address.

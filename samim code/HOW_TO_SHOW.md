# Group Project: How to show ARP and DNS from the command line

SAMIM SEKH | Roll No. 002310501026 | CSE/PC/B/S/314 Computer Networks Lab

Only standard Python is needed. Open terminals inside the `arp` or `dns` folder.

---

## Part 1: ARP

### 1a. Quick demo, one command (about 15 s)

```
python demo.py --hex
```

Add `--step` to press Enter between steps. Point out:

| Step | What to say |
|---|---|
| 1 | Each host sends a **gratuitous ARP** ("Gratuitous ARP for 192.168.1.10") when it starts. Nobody stores it, because nobody knew that host before. |
| 2 | A knows only B's IP. **Cache MISS**, so it **broadcasts** "Who has 192.168.1.20? Tell 192.168.1.10". The switch floods it to every port. C answers "not for me, ignored". B sends a **unicast reply**, and the switch sends it to A's port only. The hex dump shows the 42 bytes field by field: `08 06` = ARP, opcode `00 01` request / `00 02` reply, target MAC all zeros in the request. |
| 3 | A asks again: **cache HIT**, no packet at all. |
| 4 | B already knows A, because it **learned the asker** from the request (RFC 826), so B sends data without asking. |
| 5 | Data cannot be sent until the MAC is known: C does ARP first, then sends. |
| 6 | An IP nobody has: **3 tries, then unreachable**. |
| 7 | After the TTL the entry **expires** and A must ask again. |
| 8 | The switch's **MAC table**: one MAC per port, learned from source addresses (same idea as the 2950 switch in Assignment 6). |

### 1b. Live, in separate terminals

Terminal 1:
```
python switch.py
```
Terminal 2:
```
python host.py --name A --ip 192.168.1.10
```
Terminal 3:
```
python host.py --name B --ip 192.168.1.20
```
Terminal 4 (optional):
```
python host.py --name C --ip 192.168.1.30
```

Then type in A's terminal:

```
arp 192.168.1.20
arp 192.168.1.20
send 192.168.1.20 hello
table
arp 192.168.1.99
```

Watch the switch print *broadcast ... flooding* for the request and *unicast port 2 -> port 1 only* for the reply. Add `--hex` to a host to see its frames byte by byte, and `--ttl 10` to see expiry quickly.

**IP conflict:** start another host with B's IP but its own MAC (`python host.py --name X --ip 192.168.1.20 --mac 02:00:00:00:00:99`). The original B prints `IP ADDRESS CONFLICT` when X's gratuitous ARP arrives.

---

## Part 2: DNS

### 2a. Quick demo, one command

```
python demo.py
```

Use `--offline` if there's no internet (it skips step 6).

| Step | What to say |
|---|---|
| 1 | The server loads `zone.txt`. PTR records (IP to name) are built automatically from the A records. |
| 2 | An **A** query, with the bytes: 12-byte header, name as labels `03 www 03 cse 06 myuniv 03 edu 00`, type `00 01`, class `00 01`. The reply sets flags `85 80` = QR, AA, RD, RA. Its answer has TTL `00 00 01 2c` = 300 s and address `c0 a8 97 04` = 192.168.151.4. |
| 3 | A **CNAME chain**: portal, then web, then www, then the IP. The server follows it and returns all three records. |
| 4 | **MX** (mail server with preference 10), **NS** (who is in charge of the zone), **PTR** (reverse lookup: 192.168.151.5 is ftp). |
| 5 | **NXDOMAIN** (rcode 3): the name does not exist, said with authority. |
| 6 | Outside our zone: **forwarded** to 8.8.8.8, then **cached**. The second query is answered at once and the TTL has counted down. The **AA** flag is gone, because we don't own that zone (non-authoritative). |
| 7 | No server: **UDP gives no guarantee**, so the client retries 3 times and then gives up. |

### 2b. Live, with Windows' own nslookup

Terminal 1:
```
python dns_server.py --forward
```

If port 53 is busy, add `--port 5300` and use `-p 5300` in the client.

Terminal 2, with our client:
```
python dns_client.py www.cse.myuniv.edu --hex
python dns_client.py portal.cse.myuniv.edu
python dns_client.py cse.myuniv.edu -t MX
python dns_client.py nothere.cse.myuniv.edu
python dns_client.py www.google.com
python dns_client.py www.google.com
```

Terminal 2, with **Windows nslookup** (this proves the bytes follow the real standard):
```
nslookup www.cse.myuniv.edu 127.0.0.1
nslookup portal.cse.myuniv.edu 127.0.0.1
nslookup -type=mx cse.myuniv.edu 127.0.0.1
nslookup 192.168.151.5 127.0.0.1
```
nslookup first asks for the server's own name (a PTR query for `1.0.0.127.in-addr.arpa`), so it prints `Server: dns.cse.myuniv.edu`. For `portal` it lists `web` and `portal` as **Aliases**.

**Wireshark:** capture on *Adapter for loopback traffic capture* with filter `dns`. Wireshark decodes our packets as normal DNS.

---

## Viva questions

**ARP**
- *Why is ARP needed?* A frame needs the destination MAC, but programs know only the IP. ARP maps IP to MAC on the local network.
- *Request broadcast, reply unicast: why?* The asker doesn't know who has the IP, so it asks everyone. The owner knows exactly who asked (sender MAC in the request), so it answers only that host.
- *Which layer?* Between 2 and 3. It serves IP (layer 3) but is carried directly in an Ethernet frame (EtherType 0x0806) with no IP header, so it never crosses a router.
- *Why a cache, and why does it expire?* To avoid a broadcast before every packet. Entries expire so that a host whose MAC changed (new network card) is found again.
- *What is gratuitous ARP?* A host announcing its own IP (sender IP = target IP). It updates other caches and detects duplicate IPs.
- *Why doesn't C store A's address from the broadcast?* RFC 826: a host only adds the sender when the request is for it; otherwise it only refreshes an entry it already had.
- *Why the switch program?* Real ARP needs raw sockets, admin rights and a capture driver. The frame bytes are the real ones; only the "wire" is a UDP socket.

**DNS**
- *Why UDP?* One small question and one small answer. A TCP handshake would cost more than the lookup itself. (Real DNS uses TCP for answers over 512 bytes and for zone transfers.)
- *What does the ID field do?* It matches a reply to its query. The client ignores replies with a different ID.
- *Authoritative vs non-authoritative?* Authoritative (AA flag) means the answer comes from the server that owns the zone. Forwarded and cached answers are non-authoritative.
- *Recursive vs iterative?* RD (recursion desired) asks the server to find the full answer. Our server does that for outside names by forwarding to 8.8.8.8 (RA flag).
- *What is TTL?* How many seconds an answer may be cached. Our cache counts it down, and you can see it in the second query.
- *NXDOMAIN vs NOERROR with no answer?* NXDOMAIN: the name does not exist. NOERROR with no answer: the name exists but has no record of that type.
- *What is a compression pointer?* A repeated name is replaced by 2 bytes starting with bits `11` that point to where the name already appeared. We read them (8.8.8.8 uses them) and always write full names, which is also allowed.
- *What is a CNAME?* An alias: one name pointing to another canonical name. The server follows the chain and returns every step.

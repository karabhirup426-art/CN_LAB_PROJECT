# Basket 2: How to Demonstrate DNS in the Lab & Viva Guide

**Course:** CSE/PC/B/S/314 Computer Networks Laboratory  
**Basket 2:** Domain Name System (DNS)  
**Author:** Samim Sekh (ssk224-git)  

Only standard Python is needed. Open the terminals inside the `dns/` folder.

---

## 1. Fast Automated Demo

```bash
cd dns
python demo.py
```
*(Add `--offline` if there is no internet: it skips step 6. Add `--step` to pause and press Enter between steps.)*

### What to highlight during each step:

| Step | What to say |
|---|---|
| 1 | The server loads `zone.txt`. PTR records (IP to name) are built automatically from the A records. |
| 2 | An **A** query, with the bytes: 12-byte header, name as labels `03 www 03 cse 06 myuniv 03 edu 00`, type `00 01`, class `00 01`. The reply sets flags `85 80` = QR, AA, RD, RA (`85 00` with `--offline`, because RA is only set when forwarding is on). Its answer has TTL `00 00 01 2c` = 300 s and address `c0 a8 97 04` = 192.168.151.4. |
| 3 | A **CNAME chain**: portal, then web, then www, then the IP. The server follows it and returns all three records. |
| 4 | **MX** (mail server with preference 10), **NS** (who is in charge of the zone), **PTR** (reverse lookup: 192.168.151.5 is ftp). |
| 5 | **NXDOMAIN** (rcode 3): the name does not exist, said with authority. |
| 6 | Outside our zone: **forwarded** to 8.8.8.8, then **cached**. The second query is answered at once and the TTL has counted down. The **AA** flag is gone, because we don't own that zone (non-authoritative). |
| 7 | No server: **UDP gives no guarantee**, so the client retries 3 times and then gives up. |

---

## 2. Interactive Multi-Terminal Demo

### Terminal 1: Start the DNS Server
```bash
python dns_server.py --forward
```
If port 53 is busy, add `--port 5300` and use `-p 5300` in the client.

### Terminal 2: Queries with our client
```bash
python dns_client.py www.cse.myuniv.edu --hex
python dns_client.py portal.cse.myuniv.edu
python dns_client.py cse.myuniv.edu -t MX
python dns_client.py nothere.cse.myuniv.edu
python dns_client.py www.google.com
python dns_client.py www.google.com
```
Watch the server terminal: it prints each query and reply, the CNAME steps it follows, and *cache MISS -> asking upstream* then *cache HIT* for the two google lookups.

### Terminal 2: Queries with Windows nslookup
This proves the bytes follow the real standard:
```bash
nslookup www.cse.myuniv.edu 127.0.0.1
nslookup portal.cse.myuniv.edu 127.0.0.1
nslookup -type=mx cse.myuniv.edu 127.0.0.1
nslookup 192.168.151.5 127.0.0.1
```
nslookup first asks for the server's own name (a PTR query for `1.0.0.127.in-addr.arpa`), so it prints `Server: dns.cse.myuniv.edu`. For `portal` it lists `web` and `portal` as **Aliases**.

### Wireshark
Capture on *Adapter for loopback traffic capture* with filter `dns`. Wireshark decodes our packets as normal DNS. (Wireshark only treats port 53 as DNS, so run the server on the default port for this.)

---

## 3. High-Probability Lab Viva Questions & Model Answers

### Q1: Why does DNS use UDP?
> **Answer:** One small question and one small answer. A TCP handshake would cost more than the lookup itself. (Real DNS uses TCP for answers over 512 bytes and for zone transfers.)

### Q2: What does the ID field do?
> **Answer:** It matches a reply to its query. The client ignores replies with a different ID.

### Q3: What is the difference between an authoritative and a non-authoritative answer?
> **Answer:** Authoritative (AA flag) means the answer comes from the server that owns the zone. Forwarded and cached answers are non-authoritative.

### Q4: Recursive vs iterative resolution?
> **Answer:** RD (recursion desired) asks the server to find the full answer. Our server does that for outside names by forwarding to 8.8.8.8 (RA flag). In iterative resolution the server only says who to ask next, and the client asks again itself.

### Q5: What is TTL?
> **Answer:** How many seconds an answer may be cached. Our cache counts it down, and you can see it in the second query.

### Q6: NXDOMAIN vs NOERROR with no answer?
> **Answer:** NXDOMAIN: the name does not exist. NOERROR with no answer: the name exists but has no record of that type.

### Q7: What is a compression pointer?
> **Answer:** A repeated name is replaced by 2 bytes starting with bits `11` that point to where the name already appeared. We read them (8.8.8.8 uses them) and always write full names, which is also allowed.

### Q8: What is a CNAME?
> **Answer:** An alias: one name pointing to another canonical name. The server follows the chain and returns every step.

### Q9: How does a reverse lookup (PTR) work?
> **Answer:** The address is written backwards under `in-addr.arpa`: 192.168.151.5 becomes `5.151.168.192.in-addr.arpa`, and a PTR record there holds the name. Our server builds these from the A records in `zone.txt`.

### Q10: How does DNS connect to the other two baskets?
> **Answer:** DNS runs first: it turns `ftp.cse.myuniv.edu` into 192.168.151.5. ARP then finds the MAC address for that IP on the local network, and FTP opens its TCP connection to it.

# Computer Networks Lab - Group Project

**Course:** CSE/PC/B/S/314 Computer Networks Laboratory  
**Requirement:** Implement one protocol from each basket using TCP/UDP sockets in Python (Standard Library only).

| Basket | Protocol Chosen | Layer | Implementation Folder | Transport Protocol | RFC Specification |
|---|---|---|---|---|---|
| **Basket 1** | **ARP** (Address Resolution Protocol) | Data Link / Network | `arp/` | UDP (simulated L2 Ethernet switch) | [RFC 826](https://datatracker.ietf.org/doc/html/rfc826) / [RFC 903](https://datatracker.ietf.org/doc/html/rfc903) |
| **Basket 2** | **DNS** (Domain Name System) | Transport / Infrastructure | `samim code/dns/` | UDP port 53 / 5300 | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) |
| **Basket 3** | **FTP** (File Transfer Protocol) | Application Layer | `ftp/` | TCP port 2121 (Control) + Ephemeral (Data) | [RFC 959](https://datatracker.ietf.org/doc/html/rfc959) |

---

## The End-to-End Group Story (Connecting DNS, ARP & FTP)

Our three implementations form a complete, realistic networking pipeline from hostname resolution to secure file delivery:

```
+-----------------------------------------------------------------------------------------+
|                                    CLIENT APPLICATION                                   |
+-----------------------------------------------------------------------------------------+
       |                                      |                                    |
  1. DNS Query                           2. ARP Request                       3. TCP Session
  "Where is ftp.cse.myuniv.edu?"         "Who has 192.168.151.5?"             Connect to 2121
       |                                      |                                    |
       v                                      v                                    v
+-----------------------+              +----------------------+             +---------------------+
|      DNS SERVER       |              |  L2 LEARNING SWITCH  |             |     FTP SERVER      |
|  (samim code/dns/)    |              |       (arp/)         |             |       (ftp/)        |
| UDP Port 53 / 5300    |              | Floods broadcast     |             | Port 2121 (Control) |
| Answers 192.168.151.5 |              | Unicasts MAC reply   |             | Port PASV (Data)    |
+-----------------------+              +----------------------+             +---------------------+
```

1. **Step 1 — Domain Name Resolution (DNS, Basket 2):**  
   The client resolves `ftp.cse.myuniv.edu` using our authoritative DNS server (`dns_server.py`), which parses `zone.txt` and returns IP `192.168.151.5` with `NOERROR` and the Authoritative Answer (`AA`) bit set.
2. **Step 2 — Physical MAC Address Resolution (ARP, Basket 1):**  
   To encapsulate IP packets destined for `192.168.151.5` into Ethernet frames, the client queries its local ARP cache (`host.py`). On a Cache Miss, it broadcasts an RFC 826 ARP Request (`0x0806`) through our simulated IEEE 802.1D learning switch (`switch.py`), resolving the physical MAC `02:00:c0:a8:97:05`.
3. **Step 3 — Reliable File Transfer (FTP, Basket 3):**  
   With IP and MAC resolved, the client initiates a TCP 3-way handshake on control port 2121 to our multi-threaded FTP server (`ftp_server.py`), authenticates (`USER`/`PASS`), enters Passive Mode (`PASV`) to open an ephemeral TCP data socket, and transfers files with 100% byte-for-byte MD5 checksum verification.

---

## Interactive Protocol Visual Simulation Sandbox

An interactive web-based visual sandbox allows you to test and visualize all 3 protocols and the combined pipeline in your browser.

```bash
python3 run_visualizer.py
```
*(Automatically starts a local server and opens `http://127.0.0.1:8000/visualizer.html` in your default browser. You can also open [`visualizer.html`](visualizer.html) directly).*

### Interactive Capabilities in the Simulator:
* **Interactive ARP Sandbox (RFC 826):**
  * Click any host (`A`, `B`, `C`) on the network map and click **ARP Resolve** to watch Cache Miss broadcast flooding vs. Cache Hit ($0$ packets sent across the wire).
  * Type a custom payload and click **Send IPv4 Data**—if the MAC is unknown, the host queues the packet, runs ARP first, and delivers the `0x0800` frame.
  * Inject rogue IP conflicts (`192.168.1.20` collision alarm), broadcast Gratuitous ARP, add permanent static entries (`arp -s`), and fast-forward dynamic cache TTL timers (`⏩ Age Cache (+15s)`).
* **Interactive DNS Sandbox (RFC 1035):**
  * Query custom domains or use quick chips (`www`, `portal` CNAME chains, `MX`, `NS`, reverse `PTR`, `NXDOMAIN`).
  * Toggle `--forward (8.8.8.8)` to observe recursive upstream forwarding and cache hits, or toggle **Server Online** to test UDP timeouts and client retries.
  * Add custom records directly to `zone.txt` in real time.
* **Interactive FTP Sandbox (RFC 959):**
  * Perform the TCP 3-way handshake, authenticate with valid (`student`/`cnlab2026`, `admin`/`admin123`) or invalid passwords (`530 Auth Failed`), and switch between **PASV** (Passive) and **PORT** (Active) modes.
  * Browse directories (`PWD`, `LIST`, `CWD /pub`, `CDUP`), test sandboxing against directory traversal attacks (`CWD ../../` blocked with `550`), upload (`STOR`), download (`RETR`), and verify MD5 checksums.
* **★ End-to-End Pipeline & Wire Inspector:**
  * Step through DNS $\rightarrow$ ARP $\rightarrow$ FTP step-by-step or trigger an automated cold-start chain.
  * Hover or click any decoded field in the **Wire Packet Inspector** to highlight its exact raw hex bytes.

---

## Quick Start: Automated Demonstrations (Single Terminal)

Each protocol contains a self-contained, automated demonstration script that exercises all key protocol behaviors:

### 1. ARP Demonstration
```bash
cd arp
python3 demo.py --hex
```
*(Add `--step` to pause and press <kbd>Enter</kbd> between steps).*

### 2. DNS Demonstration
```bash
cd "samim code/dns"
python3 demo.py
```
*(Add `--offline` if you do not have an active internet connection to skip external 8.8.8.8 forwarding).*

### 3. FTP Demonstration
```bash
cd ftp
python3 demo.py
```
*(Add `--step` to pause and press <kbd>Enter</kbd> between steps, or `--quiet` to hide raw socket dumps).*

---

## Live Multi-Terminal Interactive Demonstrations

For interactive demonstrations during laboratory evaluation, run the protocols in separate terminal windows:

### Basket 1: ARP (3 Terminals)
* **Terminal 1 (Switch):**
  ```bash
  cd arp && python3 switch.py
  ```
* **Terminal 2 (Host A):**
  ```bash
  cd arp && python3 host.py --name A --ip 192.168.1.10
  ```
* **Terminal 3 (Host B):**
  ```bash
  cd arp && python3 host.py --name B --ip 192.168.1.20
  ```
* **Inside Host A (`A>` prompt):**
  ```text
  arp 192.168.1.20         # 1st query: Cache MISS -> Switch floods broadcast request
  arp 192.168.1.20         # 2nd query: Cache HIT -> Zero packets sent across the wire
  send 192.168.1.20 Hello  # Delivers IPv4 data frame
  table                    # Displays local ARP cache with TTL countdowns
  arp 192.168.1.99         # Unreachable IP: retries 3 times before timing out
  ```

### Basket 2: DNS (2 Terminals)
* **Terminal 1 (DNS Server):**
  ```bash
  cd "samim code/dns" && python3 dns_server.py --port 5300 --forward
  ```
* **Terminal 2 (DNS Client Queries):**
  ```bash
  cd "samim code/dns"
  python3 dns_client.py www.cse.myuniv.edu -p 5300 --hex
  python3 dns_client.py portal.cse.myuniv.edu -p 5300    # Traces CNAME chain
  python3 dns_client.py cse.myuniv.edu -t MX -p 5300     # Mail exchange record
  python3 dns_client.py 5.151.168.192.in-addr.arpa -t PTR -p 5300  # Reverse lookup
  python3 dns_client.py nothere.cse.myuniv.edu -p 5300   # NXDOMAIN response
  python3 dns_client.py www.google.com -p 5300           # Forwarded & cached
  ```
* **Standard OS Tool Verification:**
  ```bash
  dig @127.0.0.1 -p 5300 www.cse.myuniv.edu
  nslookup -port=5300 portal.cse.myuniv.edu 127.0.0.1
  ```

### Basket 3: FTP (2 Terminals)
* **Terminal 1 (FTP Server):**
  ```bash
  cd ftp && python3 ftp_server.py --port 2121
  ```
* **Terminal 2 (Interactive FTP Client):**
  ```bash
  cd ftp && python3 ftp_client.py --port 2121
  ```
  *(Credentials: `student` / `cnlab2026`, or `admin` / `admin123`)*
* **Inside Client (`ftp (student)>` prompt):**
  ```text
  pwd                                 # Print working directory
  ls                                  # Directory listing over PASV data socket
  put uploads/report.pdf              # Upload binary file
  size report.pdf                     # Query file size on server
  get report.pdf downloads/test.pdf   # Download file back
  cd ../../                           # Security check: rejected with 550
  quit                                # Close control session
  ```
* **Standard `curl` Verification:**
  ```bash
  curl -u student:cnlab2026 ftp://127.0.0.1:2121/
  ```

---

## Running Automated Unit Tests

Unit test suites can be executed either from the root project directory or directly inside each component folder:

### Method 1: From Root Directory (Test Discovery)
```bash
python3 -m unittest discover -s arp -v
python3 -m unittest discover -s "samim code/dns" -v
python3 -m unittest discover -s ftp -v
```

### Method 2: Inside Subdirectories
```bash
cd arp && python3 test_arp.py
cd "samim code/dns" && python3 test_dns.py
cd ftp && python3 test_ftp.py
```

---

## Repository Structure

```text
CN_LAB_PROJECT/
├── visualizer.html              # Interactive Protocol Simulation Sandbox (All 3 protocols + Stack)
├── run_visualizer.py            # Local HTTP server and auto-launcher for visualizer.html
├── README.md                    # Root project documentation and execution guide
├── LICENSE                      # MIT License
│
├── arp/                         # BASKET 1: Address Resolution Protocol (RFC 826 / RFC 903)
│   ├── arp_packet.py            # 42-byte Ethernet + ARP packet serializer/deserializer & hex dump
│   ├── switch.py                # Layer-2 IEEE 802.1D Learning Switch over UDP
│   ├── host.py                  # Host node with ARP cache, TTL, static entries, and CLI
│   ├── demo.py                  # 9-step automated laboratory demonstration script
│   ├── test_arp.py              # Unit & integration test suite (10 test cases)
│   ├── HOW_TO_SHOW_ARP.md       # Multi-terminal lab demonstration guide & viva Q&A
│   └── README.md                # Module documentation
│
├── samim code/                  # BASKET 2: Domain Name System (RFC 1035)
│   ├── dns/
│   │   ├── dns_message.py       # RFC 1035 binary message parser (labels, compression pointers)
│   │   ├── dns_server.py        # Authoritative DNS server (zone.txt, CNAME chains, forwarding)
│   │   ├── dns_client.py        # Lightweight nslookup client with retries and hex dumps
│   │   ├── zone.txt             # Authoritative zone database for cse.myuniv.edu
│   │   ├── demo.py              # Scripted demonstration of all DNS query types and caching
│   │   └── test_dns.py          # DNS message encoding and server unit test suite
│   ├── HOW_TO_SHOW.md           # Lab demonstration script and viva questions
│   └── README.md                # Module documentation
│
└── ftp/                         # BASKET 3: File Transfer Protocol (RFC 959)
    ├── ftp_server.py            # Multi-threaded RFC 959 server (Dual-socket: Control + PASV/PORT)
    ├── ftp_client.py            # Interactive socket-based FTP client shell with stats
    ├── demo.py                  # 11-step end-to-end automated transfer demonstration
    ├── test_ftp.py              # Automated test suite (Auth, PASV/PORT, MD5, traversal)
    ├── HOW_TO_SHOW_FTP.md       # Multi-terminal demonstration walkthrough & viva guide
    ├── README.md                # Module documentation
    ├── storage/                 # Server storage directory (jailed root)
    └── uploads/                 # Client sample files for upload testing
```

---

## Detailed Lab Guides & Viva Preparation

Comprehensive step-by-step demonstration scripts, Wireshark filter instructions, and examination viva questions are provided in each protocol's dedicated guide:
* **ARP Viva & Guide:** [`arp/HOW_TO_SHOW_ARP.md`](arp/HOW_TO_SHOW_ARP.md)
* **DNS Viva & Guide:** [`samim code/HOW_TO_SHOW.md`](samim%20code/HOW_TO_SHOW.md)
* **FTP Viva & Guide:** [`ftp/HOW_TO_SHOW_FTP.md`](ftp/HOW_TO_SHOW_FTP.md)

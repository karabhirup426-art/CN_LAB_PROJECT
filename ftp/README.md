# Computer Networks Lab - Group Project: File Transfer Protocol (FTP) Implementation

**Course:** Computer Networks Laboratory  
**Project Scope:** Implementation of Network, Transport, and Application Layer Protocols using TCP/UDP Sockets  
**Basket Selection:**
- **Basket 1 (Network Layer):** ARP (Address Resolution Protocol)
- **Basket 2 (Application/Transport Infrastructure):** DNS (Domain Name System)
- **Basket 3 (Application Layer):** **FTP (File Transfer Protocol)** *(This Module)*  
**Implementation Language:** Python 3 (Standard `socket` library — no third-party networking dependencies)

---

## 1. Executive Summary & Protocol Overview

The **File Transfer Protocol (FTP)** is a standard network protocol defined in **RFC 959** used to transfer computer files between a client and a server across a computer network. 

### Why TCP Sockets (and not UDP)?
FTP is implemented strictly on top of **TCP (Transmission Control Protocol)** because:
1. **Reliability & Data Integrity:** File transfer requires 100% loss-free, error-free delivery. A single dropped or corrupted bit can invalidate executable binaries, images, or documents. TCP guarantees delivery through sequence numbers, acknowledgments (ACKs), and automatic retransmissions (ARQ).
2. **Ordered Delivery:** TCP ensures packets arrive in the exact order they were sent. UDP datagrams may arrive out-of-order or duplicate.
3. **Flow and Congestion Control:** TCP utilizes sliding window flow control to prevent overwhelming the receiver's buffer and responds dynamically to network congestion.

---

## 2. FTP Dual-Connection Architecture (RFC 959)

Unlike protocols such as HTTP or SMTP that operate over a single TCP stream, standard FTP uses **two separate TCP connections** (Out-of-Band Signaling):

```
+-------------------------------------------------------------------+
|                           FTP CLIENT                              |
+-------------------------------------------------------------------+
        |                                                   |
   Control Commands                                    Data Transfer
 (USER, PWD, RETR, STOR)                                (File Bytes /
        |                                              Directory List)
        v                                                   v
+------------------+                               +----------------+
| Control Socket   |                               |  Data Socket   |
| (Port: Dynamic)  |                               | (Port: Dynamic)|
+------------------+                               +----------------+
        |                                                   |
=== TCP Control Connection (Port 2121) =============================|
        |                                                   |
=== TCP Data Connection (Negotiated dynamically via PASV/PORT) =====|
        |                                                   |
+------------------+                               +----------------+
| Server Control   |                               |  Server Data   |
| Listener (2121)  |                               | Listener (PASV)|
+------------------+                               +----------------+
        ^                                                   ^
        |                                                   |
+-------------------------------------------------------------------+
|                           FTP SERVER                              |
+-------------------------------------------------------------------+
```

1. **Control Connection (Port 2121):**
   - Remains persistently open throughout the entire client-server session.
   - Carries 7-bit ASCII command strings (`USER`, `PASS`, `LIST`, `RETR`, `STOR`, `QUIT`) and 3-digit status replies (`220`, `331`, `230`, `150`, `226`, etc.).
2. **Data Connection (Dynamically negotiated):**
   - Opened on-demand exclusively for data-intensive transfers (file uploads, file downloads, directory listings).
   - Closed immediately once the transfer is complete (sending TCP FIN).

### Passive Mode (PASV) vs Active Mode (PORT)
- **Passive Mode (`PASV` - Recommended & Default):** The client sends `PASV`. The server binds to an available ephemeral TCP port and replies with `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`. The client then initiates the TCP connection to that port. This works seamlessly across firewalls and NATs.
- **Active Mode (`PORT`):** The client opens a listening socket on its end, informs the server via `PORT h1,h2,h3,h4,p1,p2`, and the server initiates a connection back to the client.

---

## 3. Directory Layout

```
ftp_project/
├── server/
│   ├── ftp_server.py       # Multi-threaded TCP FTP Server (RFC 959)
│   └── storage/            # Server's jailed root directory for stored files
│       └── welcome.txt     # Sample server file
├── client/
│   ├── ftp_client.py       # Interactive CLI FTP Client using TCP sockets
│   ├── downloads/          # Directory where downloaded files are saved
│   └── uploads/            # Directory containing client test files to upload
│       └── upload_test.txt # Sample client upload file
├── tests/
│   └── test_ftp.py         # Automated unit & integration test suite (8 tests)
├── demo.py                 # 1-Click live demonstration script with packet trace
└── README.md               # Project documentation & lab viva preparation
```

---

## 4. Supported RFC 959 Commands & Status Codes

### Control Commands Handled:
| Command | Parameter | Description |
|---|---|---|
| `USER` | `<username>` | Specifies user identity (`admin`, `student`, `user`, `anonymous`) |
| `PASS` | `<password>` | Specifies user password |
| `PWD` | *None* | Prints current remote working directory |
| `CWD` | `<directory>` | Changes remote working directory |
| `CDUP`| *None* | Moves to parent working directory |
| `TYPE` | `<A\|I>` | Sets transfer type (`A` for ASCII, `I` for Binary) |
| `PASV` | *None* | Enters Passive Mode; server provides data port tuple |
| `PORT` | `<h1..h4,p1,p2>`| Enters Active Mode; client reports listening socket |
| `LIST` | `[path]` | Streams directory listing over data socket |
| `RETR` | `<filename>` | Downloads file from server over data socket |
| `STOR` | `<filename>` | Uploads file to server over data socket |
| `SIZE` | `<filename>` | Returns exact size of remote file in bytes |
| `DELE` | `<filename>` | Deletes remote file from server storage |
| `SYST` | *None* | Returns server operating system type |
| `NOOP` | *None* | Connection keep-alive check |
| `QUIT` | *None* | Closes session and control connection |

### Standard 3-Digit Response Codes Returned:
| Code | Explanation |
|---|---|
| `150` | File status okay; about to open data connection |
| `200` | Command okay / Mode changed |
| `213` | File status (returns file size in bytes) |
| `215` | System type reply (`UNIX Type: L8`) |
| `220` | Service ready for new user (greeting message) |
| `221` | Service closing control connection (goodbye) |
| `226` | Closing data connection; requested file action successful |
| `227` | Entering Passive Mode `(h1,h2,h3,h4,p1,p2)` |
| `230` | User logged in successfully |
| `331` | User name okay, password required |
| `425` | Can't open data connection |
| `530` | Not logged in (bad credentials) |
| `550` | Requested action not taken (file not found / permission denied) |

---

## 5. Security & Robustness Features
1. **Jailed Root Directory (Path Traversal Protection):** The server verifies canonical paths (`os.path.realpath`) and prevents attacks like `CWD ../../` or `RETR ../../../../etc/passwd`.
2. **Multi-Threaded Concurrency:** The server handles each connecting client in an isolated daemon thread (`FTPServerSession`).
3. **Graceful Socket Teardown:** Avoids `TIME_WAIT` / `Address already in use` errors using `SO_REUSEADDR`.
4. **Data Integrity Verification:** Supports binary streaming chunking (8KB buffers) and verified via MD5 hash equivalence.

---

## 6. How to Run & Test

### Option A: 1-Click Live Demonstration Script
To run an automated, end-to-end live demonstration with packet-level debugging enabled:
```bash
python3 demo.py
```
This script automatically starts the server, connects the client, authenticates, performs directory operations, uploads a file, verifies its size, downloads it back, verifies MD5 checksum equivalence, and disconnects gracefully.

---

### Option B: Interactive Manual Execution

#### Step 1: Start the FTP Server (Terminal 1)
```bash
python3 server/ftp_server.py --host 127.0.0.1 --port 2121 --root server/storage
```
*Pre-registered user accounts:*
- `student` / `cnlab2026`
- `admin` / `admin123`
- `user` / `password`
- `anonymous` / *(any password)*

#### Step 2: Start the FTP Client (Terminal 2)
```bash
python3 client/ftp_client.py --host 127.0.0.1 --port 2121
```

#### Step 3: Interactive Client Commands
```text
ftp (student)> ls                              # List files on server
ftp (student)> pwd                             # Print current directory
ftp (student)> put client/uploads/upload_test.txt # Upload file to server
ftp (student)> size upload_test.txt            # Check remote file size
ftp (student)> get upload_test.txt             # Download file to client/downloads/
ftp (student)> debug on                        # Show raw RFC 959 socket packets
ftp (student)> delete upload_test.txt          # Delete file from server
ftp (student)> quit                            # Disconnect and exit
```

---

### Option C: Automated Unit & Integration Test Suite
To execute the comprehensive automated test suite:
```bash
python3 tests/test_ftp.py
```
This runs 8 automated assertions covering:
- Authentication rejection on incorrect password (`530`)
- Authentication success (`230`)
- Anonymous login support
- Working directory operations (`PWD`, `CWD`)
- Sandbox directory traversal prevention
- 64KB binary file upload (`STOR`) + download (`RETR`) with MD5 hash integrity verification
- File size inspection (`SIZE`) and file deletion (`DELE`)
- Directory listing (`LIST`) over dynamic passive data socket

---

## 7. Computer Networks Lab Viva / Oral Exam Q&A

**Q1: At which OSI layer does FTP operate, and what transport protocol does it use?**  
*Answer:* FTP operates at the **Application Layer** (Layer 7). It relies on **TCP (Transmission Control Protocol)** at the Transport Layer because file transfers demand complete reliability, ordered delivery, and congestion/flow control.

**Q2: Why does FTP use two separate connections (Control and Data)?**  
*Answer:* FTP uses out-of-band signaling. The **Control Connection** (Port 21 or 2121) carries small ASCII commands and status codes for the entire duration of the session. The **Data Connection** is opened exclusively on-demand to transfer raw file payloads or directory listings and is closed as soon as the transfer finishes. This keeps the control channel free to send abort commands or query status while a large transfer is taking place.

**Q3: Explain the difference between Active Mode (PORT) and Passive Mode (PASV).**  
*Answer:*
- In **Active Mode (`PORT`)**, the client tells the server its IP address and a listening port number (`PORT h1,h2,h3,h4,p1,p2`). The server initiates a TCP connection to the client. This frequently fails if the client is behind a NAT router or firewall.
- In **Passive Mode (`PASV`)**, the client asks the server to listen (`PASV`). The server opens a temporary port and returns `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`. The client then initiates the TCP connection to the server. This is firewall- and NAT-friendly.

**Q4: How is the port number calculated from `(h1, h2, h3, h4, p1, p2)`?**  
*Answer:* The IP address is `h1.h2.h3.h4`. The port number is calculated using:  
$$\text{Port} = (p_1 \times 256) + p_2$$

**Q5: How does the server know when an uploaded file is finished?**  
*Answer:* In TCP socket programming, when the client finishes sending all bytes of the file, it closes the data socket (`data_sock.close()`). The TCP stack sends a **FIN** packet. On the server side, `recv()` returns an empty byte string (`b""`), signaling End-Of-File (EOF).

**Q6: What is directory traversal and how does this server prevent it?**  
*Answer:* Directory traversal (or `../` attack) occurs when an attacker requests paths like `../../etc/passwd` to access files outside the intended root folder. The server mitigates this by normalizing the target path with `os.path.abspath` and verifying that the resulting path begins with `self.root_dir`.

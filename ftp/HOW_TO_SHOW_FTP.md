## Part 3: FTP (File Transfer Protocol - RFC 959)

### 3a. Quick demo, one command (about 15 s)

```
python demo.py
```

Add `--step` to pause and press Enter between steps. Point out to the evaluator:

| Step | What to say |
|---|---|
| 1 | The server starts on **TCP control port 2121**. Note that `zone.txt` in our DNS part already maps `ftp.cse.myuniv.edu` to `192.168.151.5`. |
| 2 | Client establishes the **TCP 3-way handshake** on control port 2121. Server answers with the RFC 959 greeting: `220 Welcome to CN Lab Python Socket FTP Server`. |
| 3 | **Authentication**: `USER student` -> `331 password required`. Wrong password rejected with `530 Authentication failed`. Correct password `PASS cnlab2026` logged in with `230 User student logged in successfully`. Anonymous login is also supported. |
| 4 | Working directory query: `PWD` -> `257 "/" is the current directory`. |
| 5 | **Out-of-Band Data Connection (PASV)**: Unlike HTTP, FTP separates control from data. Client sends `PASV`. The server binds to an ephemeral TCP port and replies with `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`. Client connects to this dynamic port and requests `LIST`. Server sends `150`, streams directory entries, closes data socket, and sends `226 Directory send OK`. |
| 6 | **Upload (STOR)**: A 32 KB binary file is uploaded over a dynamic data socket. The client streams the bytes and closes the socket to signal EOF (TCP FIN). Server replies `226 Transfer complete`. |
| 7 | **File size**: `SIZE uploaded_report.pdf` returns `213 32832` bytes. |
| 8 | **Download (RETR)**: Download file back over another dynamic data connection. Throughput and transfer time are computed. |
| 9 | **Data Integrity (MD5)**: The local file's MD5 checksum matches the downloaded file's MD5 checksum byte-for-byte, proving TCP's zero packet-loss guarantee. |
| 10| **Security / Sandboxing**: Client attempts directory traversal attack (`CWD ../../`). The server intercepts and denies jailbreak (`550`), keeping the user inside the root directory. |
| 11| **Termination**: Client sends `QUIT`. Server responds `221 Goodbye` and closes the TCP control connection. |

---

### 3b. Live, in separate terminals

#### Terminal 1 (Start Server):
```
python ftp_server.py --port 2121
```

#### Terminal 2 (Interactive Client):
```
python ftp_client.py --port 2121
```
*(Login with `student` and `cnlab2026` or `admin`/`admin123`)*

Commands to demonstrate interactively:
```text
ftp (student)> ls                              # View files on server
ftp (student)> pwd                             # Print remote working directory
ftp (student)> put uploads/report.pdf          # Upload binary file over TCP data connection
ftp (student)> size report.pdf                 # Check exact byte size on server
ftp (student)> get report.pdf downloads/my.pdf # Download file over dynamic PASV connection
ftp (student)> debug on                        # Show raw RFC 959 control socket packets
ftp (student)> delete report.pdf               # Delete remote file
ftp (student)> quit                            # Graceful TCP disconnect
```

#### Demonstrating with Standard OS Tools (Proving real RFC 959 standard compliance):
Because our socket server strictly follows RFC 959, standard tools can connect to it directly:
```bash
# Terminal command-line test using curl:
curl -u student:cnlab2026 ftp://127.0.0.1:2121/

# Download a file via curl:
curl -u student:cnlab2026 ftp://127.0.0.1:2121/welcome.txt -o downloaded_welcome.txt
```

---

## The Complete End-to-End Group Story (Connecting ARP, DNS & FTP)

When explaining how all three project baskets connect together:

1. **Step 1 (DNS - Basket 2)**: A client types `ftp.cse.myuniv.edu`. The host asks our **DNS server** (`dns_server.py`). The server queries `zone.txt` and resolves `ftp.cse.myuniv.edu` to `192.168.151.5`.
2. **Step 2 (ARP - Basket 1)**: To send an IP packet to `192.168.151.5` on the local LAN, the client sends an **ARP request** broadcast ("Who has 192.168.1.x?"). The simulated switch floods it, the target host answers with a unicast ARP reply containing its MAC address, and the client caches it.
3. **Step 3 (FTP - Basket 3)**: Now that the MAC and IP are resolved, the client opens a **TCP connection** on port 2121 to our **FTP server** (`ftp_server.py`), authenticates, requests a passive data socket (`PASV`), and transfers files reliably!

---

## FTP Viva Questions & Answers

- *Why is FTP implemented over TCP instead of UDP?*  
  File transfer cannot tolerate a single dropped, duplicated, or corrupted bit. TCP provides reliable byte streaming, sequence numbers, checksums, ACK/retransmissions, and flow/congestion control. UDP offers none of these guarantees.

- *What is out-of-band signaling in FTP?*  
  FTP uses two separate connections:
  1. A persistent **Control Connection** (Port 21 / 2121) for commands and replies.
  2. A temporary **Data Connection** for each file transfer or directory listing.
  This allows control commands (e.g., aborting a transfer) to be sent while a file is actively transferring.

- *What is the difference between Passive Mode (PASV) and Active Mode (PORT)?*  
  In **Passive Mode (`PASV`)**, the server opens a temporary port and waits for the client to connect. This is firewall-friendly. In **Active Mode (`PORT`)**, the client opens a port and tells the server to connect back to it, which usually gets blocked by client-side firewalls or NAT.

- *How is the port calculated from `(h1,h2,h3,h4,p1,p2)`?*  
  The IP address is `h1.h2.h3.h4`. The port is calculated as:  
  $$\text{Port} = (p_1 \times 256) + p_2$$

- *How does the server know when an uploaded file is complete?*  
  The client closes its data socket after sending the final byte (`data_sock.close()`), which sends a TCP **FIN** packet. On the server side, `recv()` returns 0 bytes (`b""`), indicating EOF.

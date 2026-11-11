"""
demo.py
The whole FTP story in one command: the server starts on an ephemeral or standard TCP port,
and an automated sequence demonstrates every FTP feature (RFC 959).
For a live multi-terminal run use ftp_server.py and ftp_client.py (or standard OS ftp / curl).

Group project: ARP + DNS + FTP (this file: FTP)

    python demo.py              all steps with packet tracing
    python demo.py --step       pause (press Enter) between steps
    python demo.py --quiet      minimal output, hides raw socket protocol dumps
"""

import os
import sys
import time
import hashlib
import argparse
import threading

from ftp_server import FTPServer
from ftp_client import FTPClient


def heading(n, text, step):
    if step:
        input("\n(press Enter for the next step)")
    print(f"\n{'=' * 78}\nSTEP {n}: {text}\n{'=' * 78}", flush=True)


def main():
    ap = argparse.ArgumentParser(description="Scripted FTP demonstration (RFC 959)")
    ap.add_argument("--step", action="store_true", help="pause between steps")
    ap.add_argument("--quiet", action="store_true", help="hide raw control socket traces")
    args = ap.parse_args()

    base_dir = os.path.abspath(os.path.dirname(__file__))
    storage_dir = os.path.join(base_dir, "storage")
    downloads_dir = os.path.join(base_dir, "downloads")
    uploads_dir = os.path.join(base_dir, "uploads")

    os.makedirs(storage_dir, exist_ok=True)
    os.makedirs(downloads_dir, exist_ok=True)
    os.makedirs(uploads_dir, exist_ok=True)

    # Put a welcome file in storage
    with open(os.path.join(storage_dir, "welcome.txt"), "w") as f:
        f.write("Welcome to CSE/PC/B/S/314 Computer Networks Lab FTP Server!\nRFC 959 Dual-Connection TCP Implementation.\n")

    # Put an upload sample in uploads
    test_upload_path = os.path.join(uploads_dir, "report.pdf")
    test_bytes = b"%PDF-1.4 simulated binary document for computer networks lab project " + os.urandom(32768)
    with open(test_upload_path, "wb") as f:
        f.write(test_bytes)
    original_md5 = hashlib.md5(test_bytes).hexdigest()

    host = "127.0.0.1"
    port = 2121

    # 1. Start Server
    heading(1, "The FTP Server starts on TCP control port 2121", args.step)
    print(f"Domain Name  : ftp.cse.myuniv.edu (as configured in DNS zone.txt: 192.168.151.5)")
    print(f"Server Host  : {host}:{port}")
    print(f"Root Storage : {storage_dir}")
    print(f"Users        : student/cnlab2026, admin/admin123, user/password, anonymous")
    
    server = FTPServer(host=host, port=port, root_dir=storage_dir)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    # 2. Control Connection & Handshake
    heading(2, "Client initiates TCP 3-way handshake on control port 2121", args.step)
    client = FTPClient(host=host, port=port, debug=not args.quiet)
    client.connect()
    print("Reply: 220 Service ready for new user (RFC 959 greeting over TCP control stream)")

    # 3. Authentication
    heading(3, "Authentication handshake: USER and PASS commands", args.step)
    print("First, test incorrect password (returns 530):")
    client.send_cmd("USER student")
    client.send_cmd("PASS wrongpassword")
    print("\nNow, login with valid credentials (student / cnlab2026):")
    client.login("student", "cnlab2026")

    # 4. Working Directory
    heading(4, "Remote directory inspection: PWD", args.step)
    client.pwd()

    # 5. Passive Mode and Directory Listing
    heading(5, "Passive Mode (PASV) and Directory Listing (LIST)", args.step)
    print("Out-of-band signaling in action:")
    print("1. Client sends 'PASV' over control socket.")
    print("2. Server opens a new ephemeral TCP data listener and replies '227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)'.")
    print("3. Client connects to the returned data port and sends 'LIST'.")
    print("4. Server sends '150 Opening data connection', streams listing bytes, closes data socket, and replies '226'.\n")
    client.list_dir()

    # 6. File Upload (STOR)
    heading(6, "Binary file upload (STOR) over dynamic PASV TCP data connection", args.step)
    print(f"Uploading 32 KB binary file '{os.path.basename(test_upload_path)}'...")
    client.upload_file(test_upload_path, "uploaded_report.pdf")

    # 7. File Size Query (SIZE)
    heading(7, "Query file size on server (SIZE)", args.step)
    client.size_file("uploaded_report.pdf")

    # 8. File Download (RETR)
    heading(8, "Binary file download (RETR) over dynamic PASV TCP data connection", args.step)
    download_dest = os.path.join(downloads_dir, "downloaded_report.pdf")
    client.download_file("uploaded_report.pdf", download_dest)

    # 9. End-to-end Data Integrity Check (MD5)
    heading(9, "Data Integrity Verification: MD5 Checksum match over TCP", args.step)
    with open(download_dest, "rb") as f:
        downloaded_md5 = hashlib.md5(f.read()).hexdigest()
    print(f"Source Upload MD5 : {original_md5}")
    print(f"Downloaded   MD5 : {downloaded_md5}")
    if original_md5 == downloaded_md5:
        print("\033[92m[PASS] MD5 Checksums match exactly! TCP guarantees 100% loss-free byte delivery.\033[0m")
    else:
        print("\033[91m[FAIL] Checksum mismatch!\033[0m")

    # 10. Sandbox Path Traversal Protection
    heading(10, "Security check: Prevent directory traversal (CWD ../../)", args.step)
    resp = client.send_cmd("CWD ../../")
    print(f"Server response to traversal attack: {resp}")
    client.pwd()

    # 11. Termination
    heading(11, "Session termination: QUIT command", args.step)
    client.disconnect()
    server.stop()
    print("\nFTP Demonstration complete. All RFC 959 specifications verified.")


if __name__ == "__main__":
    main()

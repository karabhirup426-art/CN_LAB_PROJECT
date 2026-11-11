"""
ftp_client.py
=============
Computer Networks Lab - FTP Protocol Implementation
Application Layer Protocol Client using TCP Sockets (Python 3)

Features:
- Pure socket-based implementation (RFC 959 compliant)
- Dual-connection model: Control connection + Dynamic Data connection (PASV mode)
- Interactive CLI shell with intuitive commands
- Debug mode showing raw RFC 959 control exchanges
- File download (get/RETR) and upload (put/STOR) with speed & progress stats
- Directory browsing (ls, pwd, cd, cdup) and file inspection (size, delete)
"""

import os
import sys
import re
import socket
import time
import argparse


class FTPClient:
    def __init__(self, host="127.0.0.1", port=2121, debug=False):
        self.host = host
        self.port = port
        self.debug = debug
        self.control_sock = None
        self.is_connected = False
        self.is_logged_in = False
        self.current_user = None

    def log_debug(self, prefix, message):
        if self.debug:
            print(f"\033[90m[{prefix}] {message.strip()}\033[0m")

    def connect(self, host=None, port=None):
        if host:
            self.host = host
        if port:
            self.port = int(port)

        if self.is_connected:
            self.disconnect()

        try:
            self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_sock.settimeout(15.0)
            print(f"[*] Connecting to FTP server at {self.host}:{self.port} over TCP...")
            self.control_sock.connect((self.host, self.port))
            self.is_connected = True

            welcome_msg = self.read_response()
            print(f"[+] Connected! Server greeting: {welcome_msg}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            self.control_sock = None
            self.is_connected = False
            return False

    def send_cmd(self, command):
        """Send command over TCP control connection."""
        if not self.is_connected or not self.control_sock:
            print("[-] Error: Not connected to an FTP server. Use 'connect <host> <port>' first.")
            return None

        line = command.strip() + "\r\n"
        self.log_debug("CTRL >>", command.strip())
        try:
            self.control_sock.sendall(line.encode("utf-8"))
            return self.read_response()
        except socket.error as e:
            print(f"[-] Control socket communication error: {e}")
            self.disconnect()
            return None

    def read_response(self):
        """Read FTP reply code and text from control connection."""
        try:
            raw = b""
            while True:
                chunk = self.control_sock.recv(1024)
                if not chunk:
                    break
                raw += chunk
                if b"\r\n" in raw:
                    break

            response = raw.decode("utf-8", errors="replace").strip()
            self.log_debug("CTRL <<", response)
            return response
        except socket.timeout:
            print("[-] Control socket timed out waiting for server response.")
            return ""
        except socket.error as e:
            print(f"[-] Error reading from control socket: {e}")
            return ""

    def get_code(self, response):
        """Extracts the 3-digit status code from the server response."""
        if not response or len(response) < 3:
            return 0
        try:
            return int(response[:3])
        except ValueError:
            return 0

    def login(self, username=None, password=None):
        """Authenticate user with USER and PASS."""
        if not self.is_connected:
            print("[-] Must connect to server first.")
            return False

        if not username:
            username = input("Username [anonymous]: ").strip() or "anonymous"

        resp = self.send_cmd(f"USER {username}")
        code = self.get_code(resp)

        if code == 331:
            if password is None:
                if username == "anonymous":
                    password = "guest@"
                else:
                    import getpass
                    password = getpass.getpass("Password: ")
            resp = self.send_cmd(f"PASS {password}")
            code = self.get_code(resp)

        if code == 230:
            print(f"[+] Login successful as '{username}'.")
            self.is_logged_in = True
            self.current_user = username
            return True
        else:
            print(f"[-] Login failed: {resp}")
            self.is_logged_in = False
            return False

    def open_passive_data_connection(self):
        """
        Sends PASV command, parses IP & Port from response:
        '227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)'
        and opens a TCP connection to that address.
        """
        resp = self.send_cmd("PASV")
        code = self.get_code(resp)
        if code != 227:
            print(f"[-] Failed to enter passive mode: {resp}")
            return None

        # Parse (h1,h2,h3,h4,p1,p2)
        match = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", resp)
        if not match:
            print(f"[-] Invalid PASV response format: {resp}")
            return None

        parts = [int(p) for p in match.groups()]
        pasv_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}"
        pasv_port = parts[4] * 256 + parts[5]

        # If server returns 0.0.0.0 or 127.0.0.1 while we connected via specific host, reuse self.host
        if pasv_ip == "0.0.0.0":
            pasv_ip = self.host

        self.log_debug("DATA", f"Connecting to data port {pasv_ip}:{pasv_port}...")
        try:
            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_sock.settimeout(15.0)
            data_sock.connect((pasv_ip, pasv_port))
            return data_sock
        except Exception as e:
            print(f"[-] Failed to open data connection to {pasv_ip}:{pasv_port}: {e}")
            return None

    def list_dir(self, path=""):
        """Perform LIST command over PASV data connection."""
        data_sock = self.open_passive_data_connection()
        if not data_sock:
            return

        cmd = f"LIST {path}".strip()
        resp = self.send_cmd(cmd)
        code = self.get_code(resp)
        if code != 150:
            print(f"[-] Server refused LIST command: {resp}")
            data_sock.close()
            return

        print(f"[*] Directory Listing ({resp}):")
        print("-" * 65)
        raw_data = b""
        while True:
            chunk = data_sock.recv(4096)
            if not chunk:
                break
            raw_data += chunk
        data_sock.close()

        listing_str = raw_data.decode("utf-8", errors="replace")
        if listing_str.strip():
            print(listing_str.rstrip())
        else:
            print("(Directory is empty)")
        print("-" * 65)

        completion_resp = self.read_response()
        self.log_debug("STATUS", completion_resp)

    def pwd(self):
        resp = self.send_cmd("PWD")
        print(resp)

    def cwd(self, target_dir):
        if not target_dir:
            print("[-] Usage: cd <directory>")
            return
        resp = self.send_cmd(f"CWD {target_dir}")
        print(resp)

    def cdup(self):
        resp = self.send_cmd("CDUP")
        print(resp)

    def download_file(self, remote_file, local_file=None):
        """
        Download file (RETR) using PASV data socket.
        Saves locally and computes transfer throughput.
        """
        if not remote_file:
            print("[-] Usage: get <remote_filename> [local_destination]")
            return

        if not local_file:
            local_file = os.path.basename(remote_file)

        # Make sure destination folder exists
        dest_dir = os.path.dirname(local_file)
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)

        data_sock = self.open_passive_data_connection()
        if not data_sock:
            return

        resp = self.send_cmd(f"RETR {remote_file}")
        code = self.get_code(resp)
        if code != 150:
            print(f"[-] Server error: {resp}")
            data_sock.close()
            return

        print(f"[*] Downloading '{remote_file}' -> '{local_file}'...")
        start_time = time.time()
        bytes_received = 0

        try:
            with open(local_file, "wb") as f:
                while True:
                    chunk = data_sock.recv(8192)
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
            data_sock.close()

            elapsed = max(time.time() - start_time, 0.0001)
            rate_kb = (bytes_received / 1024.0) / elapsed
            print(f"[+] Download complete: {bytes_received} bytes in {elapsed:.3f}s ({rate_kb:.2f} KB/s)")

            final_resp = self.read_response()
            self.log_debug("STATUS", final_resp)
        except Exception as e:
            print(f"[-] Download error: {e}")
            try:
                data_sock.close()
            except Exception:
                pass

    def upload_file(self, local_file, remote_file=None):
        """
        Upload file (STOR) using PASV data socket.
        Streams local file to server and prints stats.
        """
        if not local_file:
            print("[-] Usage: put <local_filepath> [remote_filename]")
            return

        if not os.path.isfile(local_file):
            print(f"[-] Local file not found: {local_file}")
            return

        if not remote_file:
            remote_file = os.path.basename(local_file)

        data_sock = self.open_passive_data_connection()
        if not data_sock:
            return

        resp = self.send_cmd(f"STOR {remote_file}")
        code = self.get_code(resp)
        if code != 150:
            print(f"[-] Server refused upload: {resp}")
            data_sock.close()
            return

        file_size = os.path.getsize(local_file)
        print(f"[*] Uploading '{local_file}' ({file_size} bytes) -> '{remote_file}'...")
        start_time = time.time()
        bytes_sent = 0

        try:
            with open(local_file, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    data_sock.sendall(chunk)
                    bytes_sent += len(chunk)

            # Close data socket to signal EOF (TCP FIN) to server
            data_sock.close()

            elapsed = max(time.time() - start_time, 0.0001)
            rate_kb = (bytes_sent / 1024.0) / elapsed
            print(f"[+] Upload complete: {bytes_sent} bytes in {elapsed:.3f}s ({rate_kb:.2f} KB/s)")

            final_resp = self.read_response()
            print(f"[+] Server: {final_resp}")
        except Exception as e:
            print(f"[-] Upload error: {e}")
            try:
                data_sock.close()
            except Exception:
                pass

    def delete_file(self, filename):
        if not filename:
            print("[-] Usage: delete <remote_filename>")
            return
        resp = self.send_cmd(f"DELE {filename}")
        print(resp)

    def size_file(self, filename):
        if not filename:
            print("[-] Usage: size <remote_filename>")
            return
        resp = self.send_cmd(f"SIZE {filename}")
        print(resp)

    def disconnect(self):
        if self.is_connected and self.control_sock:
            try:
                self.send_cmd("QUIT")
            except Exception:
                pass
            try:
                self.control_sock.close()
            except Exception:
                pass
        self.control_sock = None
        self.is_connected = False
        self.is_logged_in = False
        self.current_user = None
        print("[*] Disconnected from server.")

    def run_shell(self):
        """Interactive REPL prompt for lab demonstration."""
        print("=" * 65)
        print("   PYTHON TCP SOCKET FTP CLIENT (RFC 959)")
        print("=" * 65)
        print(" Type 'help' to see available commands.")
        print(" Type 'connect <host> <port>' to initiate connection.")
        print(" Type 'debug on' to inspect raw RFC 959 socket packets.")
        print("=" * 65)

        # Auto-connect initially if server is running locally
        if self.connect():
            self.login()

        while True:
            try:
                prompt_user = self.current_user if self.is_logged_in else "offline"
                cmd_line = input(f"ftp ({prompt_user})> ").strip()
                if not cmd_line:
                    continue

                parts = cmd_line.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd in ["quit", "exit", "bye"]:
                    self.disconnect()
                    print("Goodbye!")
                    break
                elif cmd == "help":
                    self.print_help()
                elif cmd == "connect" or cmd == "open":
                    h = args[0] if len(args) > 0 else "127.0.0.1"
                    p = int(args[1]) if len(args) > 1 else 2121
                    if self.connect(h, p):
                        self.login()
                elif cmd == "login" or cmd == "user":
                    u = args[0] if len(args) > 0 else None
                    p = args[1] if len(args) > 1 else None
                    self.login(u, p)
                elif cmd in ["ls", "dir"]:
                    path = args[0] if len(args) > 0 else ""
                    self.list_dir(path)
                elif cmd == "pwd":
                    self.pwd()
                elif cmd == "cd":
                    if not args:
                        print("[-] Usage: cd <path>")
                    else:
                        self.cwd(args[0])
                elif cmd == "cdup":
                    self.cdup()
                elif cmd in ["get", "download"]:
                    if not args:
                        print("[-] Usage: get <remote_file> [local_file]")
                    else:
                        rem = args[0]
                        loc = args[1] if len(args) > 1 else os.path.join("./downloads", os.path.basename(rem))
                        self.download_file(rem, loc)
                elif cmd in ["put", "upload"]:
                    if not args:
                        print("[-] Usage: put <local_file> [remote_file]")
                    else:
                        loc = args[0]
                        rem = args[1] if len(args) > 1 else os.path.basename(loc)
                        self.upload_file(loc, rem)
                elif cmd in ["del", "delete", "rm"]:
                    if not args:
                        print("[-] Usage: delete <remote_file>")
                    else:
                        self.delete_file(args[0])
                elif cmd == "size":
                    if not args:
                        print("[-] Usage: size <remote_file>")
                    else:
                        self.size_file(args[0])
                elif cmd == "debug":
                    if args and args[0].lower() == "on":
                        self.debug = True
                        print("[*] Debug packet logging enabled.")
                    elif args and args[0].lower() == "off":
                        self.debug = False
                        print("[*] Debug packet logging disabled.")
                    else:
                        self.debug = not self.debug
                        print(f"[*] Debug packet logging is now: {'ON' if self.debug else 'OFF'}")
                elif cmd == "raw":
                    # Send arbitrary raw RFC 959 command
                    raw_cmd = " ".join(args)
                    resp = self.send_cmd(raw_cmd)
                    print(resp)
                else:
                    print(f"[-] Unknown command '{cmd}'. Type 'help' for available commands.")
            except (KeyboardInterrupt, EOFError):
                print()
                self.disconnect()
                break

    def print_help(self):
        print("""
Available FTP Client Commands:
  connect [host] [port]   - Connect to FTP server (default: 127.0.0.1 2121)
  login [user] [pass]     - Authenticate with server
  ls / dir [path]         - List files in current or target directory (PASV)
  pwd                     - Print current remote working directory
  cd <dir>                - Change remote working directory
  cdup                    - Move to parent directory
  get <remote> [local]    - Download file from server over data connection
  put <local> [remote]    - Upload file to server over data connection
  size <file>             - Query file size in bytes
  delete <file>           - Delete remote file
  debug [on|off]          - Toggle display of raw RFC 959 socket packets
  raw <FTP command>       - Send raw FTP command (e.g. 'raw SYST', 'raw TYPE I')
  help                    - Display this command reference
  quit / exit             - Disconnect and exit client
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Socket-Based FTP Client (RFC 959)")
    parser.add_argument("--host", default="127.0.0.1", help="Server host IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=2121, help="Server port (default: 2121)")
    parser.add_argument("--debug", action="store_true", help="Enable raw socket debug logging")
    args = parser.parse_args()

    client = FTPClient(host=args.host, port=args.port, debug=args.debug)
    client.run_shell()

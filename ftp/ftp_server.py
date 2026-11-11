"""
ftp_server.py
=============
Computer Networks Lab - FTP Protocol Implementation
Application Layer Protocol implemented using TCP Sockets (Python 3)

Features:
- Dual-connection RFC 959 architecture: Control Connection + Data Connection
- Supports both Passive Mode (PASV) and Active Mode (PORT)
- Multi-client concurrency using Threading
- Sandboxed directory root (Path Traversal Protection)
- Supported Commands: USER, PASS, PWD, CWD, CDUP, TYPE, PASV, PORT,
                     LIST, NLST, RETR, STOR, DELE, SIZE, SYST, NOOP, QUIT
"""

import os
import sys
import socket
import threading
import time
import datetime


class FTPServerSession(threading.Thread):
    def __init__(self, client_sock, client_addr, root_dir, users_db, server_ip="127.0.0.1"):
        super().__init__(daemon=True)
        self.control_sock = client_sock
        self.client_addr = client_addr
        self.root_dir = os.path.abspath(root_dir)
        self.cwd = "/"  # Virtual working directory relative to root_dir
        self.users_db = users_db  # dict: {username: password}
        self.server_ip = server_ip

        # Session state
        self.username = None
        self.is_authenticated = False
        self.binary_mode = True

        # Data connection state
        self.pasv_listener = None
        self.active_data_addr = None  # (ip, port) for PORT mode

        self.running = True

    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{self.client_addr[0]}:{self.client_addr[1]}] {message}")

    def send_response(self, code, text):
        """Send standard FTP response line to client over control connection."""
        response = f"{code} {text}\r\n"
        self.log(f">> {code} {text}")
        try:
            self.control_sock.sendall(response.encode("utf-8"))
        except (socket.error, BrokenPipeError):
            self.running = False

    def to_absolute_path(self, virtual_path):
        """
        Converts a virtual FTP path to a safe local filesystem path.
        Prevents directory traversal outside root_dir.
        """
        if virtual_path.startswith("/"):
            combined = os.path.normpath(virtual_path.lstrip("/"))
        else:
            combined = os.path.normpath(os.path.join(self.cwd.lstrip("/"), virtual_path))

        abs_path = os.path.abspath(os.path.join(self.root_dir, combined))

        # Check sandbox escape
        if not abs_path.startswith(self.root_dir):
            return None
        return abs_path

    def to_virtual_path(self, abs_path):
        """Converts an absolute filesystem path back to virtual FTP path."""
        rel = os.path.relpath(abs_path, self.root_dir)
        if rel == ".":
            return "/"
        return "/" + rel.replace(os.sep, "/")

    def open_data_connection(self):
        """
        Establishes the data socket (either accepts incoming PASV connection
        or initiates active connection to PORT address).
        """
        data_sock = None
        if self.pasv_listener is not None:
            # Passive mode: wait for client to connect to listener
            try:
                self.pasv_listener.settimeout(10.0)
                data_sock, _ = self.pasv_listener.accept()
                self.log(f"Data connection established (PASV)")
            except socket.timeout:
                self.log("Timeout waiting for PASV data connection")
            finally:
                self.pasv_listener.close()
                self.pasv_listener = None
        elif self.active_data_addr is not None:
            # Active mode: server connects to client's reported address
            try:
                data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_sock.settimeout(10.0)
                data_sock.connect(self.active_data_addr)
                self.log(f"Connected to client for data connection (PORT {self.active_data_addr})")
            except Exception as e:
                self.log(f"Failed to connect to PORT {self.active_data_addr}: {e}")
                data_sock = None
            finally:
                self.active_data_addr = None

        return data_sock

    def run(self):
        self.log("Client connected. Starting FTP control session.")
        self.send_response(220, "Welcome to CN Lab Python Socket FTP Server (RFC 959)")

        buffer = ""
        while self.running:
            try:
                chunk = self.control_sock.recv(1024)
                if not chunk:
                    break
                buffer += chunk.decode("utf-8", errors="replace")

                while "\r\n" in buffer or "\n" in buffer:
                    if "\r\n" in buffer:
                        line, buffer = buffer.split("\r\n", 1)
                    else:
                        line, buffer = buffer.split("\n", 1)

                    line = line.strip()
                    if not line:
                        continue

                    self.log(f"<< {line}")
                    self.process_command(line)
            except (socket.error, ConnectionResetError) as e:
                self.log(f"Connection error: {e}")
                break
            except Exception as e:
                self.log(f"Unexpected error: {e}")
                break

        self.cleanup()
        self.log("Client disconnected. Session closed.")

    def cleanup(self):
        self.running = False
        if self.pasv_listener:
            try:
                self.pasv_listener.close()
            except Exception:
                pass
            self.pasv_listener = None
        try:
            self.control_sock.close()
        except Exception:
            pass

    def process_command(self, line):
        parts = line.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        # Unauthenticated commands
        if cmd == "USER":
            self.handle_user(arg)
            return
        elif cmd == "PASS":
            self.handle_pass(arg)
            return
        elif cmd == "QUIT":
            self.send_response(221, "Goodbye! Closing control connection.")
            self.running = False
            return
        elif cmd == "NOOP":
            self.send_response(200, "NOOP OK.")
            return

        # Commands requiring authentication
        if not self.is_authenticated:
            self.send_response(530, "Please login with USER and PASS first.")
            return

        if cmd == "PWD" or cmd == "XPWD":
            self.send_response(257, f'"{self.cwd}" is the current directory.')
        elif cmd == "CWD":
            self.handle_cwd(arg)
        elif cmd == "CDUP":
            self.handle_cdup()
        elif cmd == "TYPE":
            self.handle_type(arg)
        elif cmd == "PASV":
            self.handle_pasv()
        elif cmd == "PORT":
            self.handle_port(arg)
        elif cmd == "LIST" or cmd == "NLST":
            self.handle_list(arg, names_only=(cmd == "NLST"))
        elif cmd == "RETR":
            self.handle_retr(arg)
        elif cmd == "STOR":
            self.handle_stor(arg)
        elif cmd == "DELE":
            self.handle_dele(arg)
        elif cmd == "SIZE":
            self.handle_size(arg)
        elif cmd == "SYST":
            self.send_response(215, "UNIX Type: L8 (Python Socket Lab FTP)")
        elif cmd == "FEAT":
            self.send_response(211, "Features supported: PASV, PORT, RETR, STOR, LIST, SIZE, PWD, CWD")
        else:
            self.send_response(502, f"Command '{cmd}' not implemented.")

    # ------------------ Command Handlers ------------------

    def handle_user(self, username):
        if not username:
            self.send_response(501, "Syntax error in parameters (username required).")
            return
        self.username = username.strip()
        self.is_authenticated = False
        if self.username == "anonymous":
            self.send_response(331, "Guest login ok, send your complete e-mail address as password.")
        else:
            self.send_response(331, f"User name {self.username} okay, password required.")

    def handle_pass(self, password):
        if not self.username:
            self.send_response(503, "Login with USER first.")
            return

        # Check authentication
        if self.username == "anonymous":
            self.is_authenticated = True
            self.send_response(230, "Anonymous user logged in successfully.")
        elif self.username in self.users_db and self.users_db[self.username] == password:
            self.is_authenticated = True
            self.send_response(230, f"User {self.username} logged in successfully.")
        else:
            self.is_authenticated = False
            self.send_response(530, "Authentication failed. Incorrect username or password.")

    def handle_cwd(self, target_dir):
        if not target_dir:
            self.send_response(501, "Directory path required.")
            return

        abs_path = self.to_absolute_path(target_dir)
        if abs_path and os.path.isdir(abs_path):
            self.cwd = self.to_virtual_path(abs_path)
            self.send_response(250, f'Directory changed to "{self.cwd}".')
        else:
            self.send_response(550, f"Failed to change directory. '{target_dir}' does not exist.")

    def handle_cdup(self):
        parent = os.path.dirname(self.cwd.rstrip("/"))
        if not parent:
            parent = "/"
        abs_path = self.to_absolute_path(parent)
        if abs_path and os.path.isdir(abs_path):
            self.cwd = self.to_virtual_path(abs_path)
            self.send_response(200, f'Directory changed to "{self.cwd}".')
        else:
            self.send_response(550, "Cannot change to parent directory.")

    def handle_type(self, type_arg):
        arg = type_arg.upper().strip()
        if arg == "A":
            self.binary_mode = False
            self.send_response(200, "Switching to ASCII mode.")
        elif arg == "I":
            self.binary_mode = True
            self.send_response(200, "Switching to Binary mode.")
        else:
            self.send_response(504, f"Command not implemented for TYPE {arg}.")

    def handle_pasv(self):
        """
        Passive Mode: Server opens a listening TCP port and sends the
        (h1,h2,h3,h4,p1,p2) response so client can connect to it.
        """
        if self.pasv_listener:
            try:
                self.pasv_listener.close()
            except Exception:
                pass

        try:
            self.pasv_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.pasv_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind to server IP and let OS pick an available ephemeral port (0)
            self.pasv_listener.bind((self.server_ip, 0))
            self.pasv_listener.listen(1)

            pasv_port = self.pasv_listener.getsockname()[1]

            # Convert IP to h1,h2,h3,h4
            # If server_ip is 0.0.0.0, use the local address of the control connection
            effective_ip = self.server_ip
            if effective_ip == "0.0.0.0":
                effective_ip = self.control_sock.getsockname()[0]

            h_parts = effective_ip.split(".")
            p1 = pasv_port // 256
            p2 = pasv_port % 256

            pasv_string = f"{h_parts[0]},{h_parts[1]},{h_parts[2]},{h_parts[3]},{p1},{p2}"
            self.send_response(227, f"Entering Passive Mode ({pasv_string})")
            self.log(f"Passive listener opened on {effective_ip}:{pasv_port}")
        except Exception as e:
            self.send_response(425, f"Can't open passive connection: {e}")

    def handle_port(self, port_arg):
        """
        Active Mode: Client sends PORT h1,h2,h3,h4,p1,p2.
        Server records client's data IP:Port to connect later.
        """
        try:
            parts = [int(p) for p in port_arg.split(",")]
            if len(parts) != 6:
                raise ValueError("PORT command requires 6 comma-separated numbers.")
            ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}"
            port = parts[4] * 256 + parts[5]
            self.active_data_addr = (ip, port)
            self.send_response(200, f"PORT command successful ({ip}:{port}).")
        except Exception as e:
            self.send_response(501, f"Illegal PORT command: {e}")

    def handle_list(self, path_arg, names_only=False):
        """Send directory listing over data connection."""
        target = path_arg if path_arg else self.cwd
        abs_path = self.to_absolute_path(target)

        if not abs_path or not os.path.exists(abs_path):
            self.send_response(550, f"Path '{target}' not found.")
            return

        data_sock = self.open_data_connection()
        if not data_sock:
            self.send_response(425, "Can't open data connection.")
            return

        self.send_response(150, "Here comes the directory listing.")
        try:
            listing = []
            if os.path.isdir(abs_path):
                entries = sorted(os.listdir(abs_path))
                for entry in entries:
                    if entry.startswith(".") and not path_arg.startswith("-a"):
                        continue
                    full_p = os.path.join(abs_path, entry)
                    if names_only:
                        listing.append(f"{entry}\r\n")
                    else:
                        # Emulate standard Unix 'ls -l' output for FTP clients
                        stat = os.stat(full_p)
                        is_dir = "d" if os.path.isdir(full_p) else "-"
                        perms = f"{is_dir}rw-r--r--"
                        size = stat.st_size
                        mtime = time.strftime("%b %d %H:%M", time.localtime(stat.st_mtime))
                        listing.append(f"{perms} 1 owner group {size:>10} {mtime} {entry}\r\n")
            else:
                # Target is a file
                stat = os.stat(abs_path)
                entry = os.path.basename(abs_path)
                perms = "-rw-r--r--"
                size = stat.st_size
                mtime = time.strftime("%b %d %H:%M", time.localtime(stat.st_mtime))
                listing.append(f"{perms} 1 owner group {size:>10} {mtime} {entry}\r\n")

            data_content = "".join(listing).encode("utf-8")
            data_sock.sendall(data_content)
            data_sock.close()
            self.send_response(226, "Directory send OK.")
        except Exception as e:
            self.log(f"Error during LIST: {e}")
            self.send_response(451, f"Failed to send directory listing: {e}")
        finally:
            try:
                data_sock.close()
            except Exception:
                pass

    def handle_retr(self, filename):
        """Handle file download (RETR) from server to client."""
        if not filename:
            self.send_response(501, "Filename required for RETR.")
            return

        abs_path = self.to_absolute_path(filename)
        if not abs_path or not os.path.isfile(abs_path):
            self.send_response(550, f"File '{filename}' not found.")
            return

        data_sock = self.open_data_connection()
        if not data_sock:
            self.send_response(425, "Can't open data connection.")
            return

        file_size = os.path.getsize(abs_path)
        mode_str = "BINARY" if self.binary_mode else "ASCII"
        self.send_response(150, f"Opening {mode_str} mode data connection for {filename} ({file_size} bytes).")

        try:
            bytes_sent = 0
            open_mode = "rb" if self.binary_mode else "r"
            encoding = None if self.binary_mode else "utf-8"

            with open(abs_path, open_mode, encoding=encoding) as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    if not self.binary_mode:
                        chunk = chunk.encode("utf-8")
                    data_sock.sendall(chunk)
                    bytes_sent += len(chunk)

            data_sock.close()
            self.log(f"RETR successful: {bytes_sent} bytes transferred.")
            self.send_response(226, "Transfer complete.")
        except Exception as e:
            self.log(f"Error during RETR: {e}")
            self.send_response(426, f"Connection closed; transfer aborted: {e}")
        finally:
            try:
                data_sock.close()
            except Exception:
                pass

    def handle_stor(self, filename):
        """Handle file upload (STOR) from client to server."""
        if not filename:
            self.send_response(501, "Filename required for STOR.")
            return

        abs_path = self.to_absolute_path(filename)
        if not abs_path:
            self.send_response(550, "Invalid destination path (access denied).")
            return

        data_sock = self.open_data_connection()
        if not data_sock:
            self.send_response(425, "Can't open data connection.")
            return

        mode_str = "BINARY" if self.binary_mode else "ASCII"
        self.send_response(150, f"Ok to send data (Mode: {mode_str}).")

        try:
            bytes_received = 0
            open_mode = "wb" if self.binary_mode else "w"
            encoding = None if self.binary_mode else "utf-8"

            with open(abs_path, open_mode, encoding=encoding) as f:
                while True:
                    chunk = data_sock.recv(8192)
                    if not chunk:
                        break
                    if not self.binary_mode:
                        f.write(chunk.decode("utf-8", errors="replace"))
                    else:
                        f.write(chunk)
                    bytes_received += len(chunk)

            data_sock.close()
            self.log(f"STOR successful: {bytes_received} bytes received into {abs_path}.")
            self.send_response(226, f"Transfer complete ({bytes_received} bytes received).")
        except Exception as e:
            self.log(f"Error during STOR: {e}")
            self.send_response(426, f"Connection closed; transfer aborted: {e}")
        finally:
            try:
                data_sock.close()
            except Exception:
                pass

    def handle_dele(self, filename):
        if not filename:
            self.send_response(501, "Filename required for DELE.")
            return

        abs_path = self.to_absolute_path(filename)
        if abs_path and os.path.isfile(abs_path):
            try:
                os.remove(abs_path)
                self.send_response(250, f"File '{filename}' deleted successfully.")
            except Exception as e:
                self.send_response(550, f"Cannot delete file: {e}")
        else:
            self.send_response(550, f"File '{filename}' not found.")

    def handle_size(self, filename):
        if not filename:
            self.send_response(501, "Filename required for SIZE.")
            return

        abs_path = self.to_absolute_path(filename)
        if abs_path and os.path.isfile(abs_path):
            size = os.path.getsize(abs_path)
            self.send_response(213, str(size))
        else:
            self.send_response(550, f"File '{filename}' not found.")


class FTPServer:
    def __init__(self, host="127.0.0.1", port=2121, root_dir="./storage"):
        self.host = host
        self.port = port
        self.root_dir = os.path.abspath(root_dir)
        os.makedirs(self.root_dir, exist_ok=True)

        # Default registered user database
        self.users = {
            "admin": "admin123",
            "user": "password",
            "student": "cnlab2026"
        }

        self.server_sock = None
        self.is_running = False

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_sock.bind((self.host, self.port))
            self.server_sock.listen(10)
            self.is_running = True
            print("=" * 65)
            print("   PYTHON TCP SOCKET FTP SERVER (RFC 959)")
            print("=" * 65)
            print(f" Control Address : {self.host}:{self.port}")
            print(f" Root Directory   : {self.root_dir}")
            print(f" Users available : {list(self.users.keys())} + 'anonymous'")
            print(" Waiting for client connections (Press Ctrl+C to stop)...")
            print("=" * 65)

            while self.is_running:
                try:
                    client_sock, client_addr = self.server_sock.accept()
                    session = FTPServerSession(
                        client_sock=client_sock,
                        client_addr=client_addr,
                        root_dir=self.root_dir,
                        users_db=self.users,
                        server_ip=self.host
                    )
                    session.start()
                except socket.error:
                    break
        except KeyboardInterrupt:
            print("\nShutting down FTP server...")
        finally:
            self.stop()

    def stop(self):
        self.is_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        print("FTP Server stopped.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Python Socket-Based FTP Server (RFC 959)")
    parser.add_argument("--host", default="127.0.0.1", help="Host IP to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=2121, help="Port to listen on (default: 2121)")
    parser.add_argument("--root", default="./storage", help="Root storage directory (default: ./storage)")
    args = parser.parse_args()

    server = FTPServer(host=args.host, port=args.port, root_dir=args.root)
    server.start()

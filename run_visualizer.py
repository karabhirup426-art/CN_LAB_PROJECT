#!/usr/bin/env python3
"""
run_visualizer.py
=================
Launches a lightweight local HTTP server and opens the interactive visual simulation
of ARP, DNS, and FTP in your default web browser.

Usage:
  python3 run_visualizer.py
"""

import http.server
import socketserver
import webbrowser
import os
import sys

DEFAULT_PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        # Suppress normal static file access logs for a clean CLI
        pass

def main():
    port = DEFAULT_PORT
    server = None
    for p in range(DEFAULT_PORT, DEFAULT_PORT + 20):
        try:
            server = socketserver.TCPServer(("127.0.0.1", p), QuietHandler)
            port = p
            break
        except OSError:
            continue

    if not server:
        print("[-] Could not bind to an open port between 8000 and 8020.")
        sys.exit(1)

    url = f"http://127.0.0.1:{port}/visualizer.html"
    print("=" * 65)
    print("   CN LAB PROTOCOL VISUAL SIMULATOR (ARP • DNS • FTP)")
    print("=" * 65)
    print(f"[*] Visual simulator running at: {url}")
    print("[*] Opening your web browser automatically...")
    print("[*] Press Ctrl+C in this terminal to stop the server.")
    print("=" * 65)

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Visual simulator server stopped.")

if __name__ == "__main__":
    main()


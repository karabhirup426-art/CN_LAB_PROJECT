"""
host.py
Ethernet Host with Local ARP Cache, Gratuitous ARP & Data Transmission
=====================================================================
Course: CSE/PC/B/S/314 Computer Networks Laboratory
Basket 1: Address Resolution Protocol (ARP)
Author: Sk Amanullah (skaman75)

THE PROBLEM ARP SOLVES:
  Network applications specify target IPv4 addresses, but Layer-2 Ethernet
  network interface cards (NICs) require physical MAC addresses to encapsulate
  frames. ARP bridges Layer 3 (IPv4) to Layer 2 (Ethernet).

KEY FEATURES IMPLEMENTED:
  1. Local ARP Cache with TTL expiration and Cache Hit/Miss logic.
  2. Static ARP Entries (Permanent, like `arp -s`) and Deletions (`arp -d`).
  3. Reverse ARP (RFC 903 RARP) resolution.
  4. Passive Asker Learning (RFC 826):
     When Host B receives an ARP request from Host A, B learns A's IP/MAC immediately,
     avoiding a redundant ARP broadcast when B replies or transmits back to A.
  5. Gratuitous ARP & IP Address Conflict Detection:
     Detects if a rogue host on the subnet claims our own IP address.
  6. Layer-3 Data Encapsulation:
     Demonstrates that sending higher-layer IPv4 data (`send <ip> <msg>`)
     is blocked until ARP resolves the destination MAC address.
  7. Retries & Timeout:
     Retries 3 times on unanswered queries before marking target unreachable.
"""

import argparse
import socket
import sys
import threading
import time
from dataclasses import dataclass

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from arp_packet import (
    BROADCAST_MAC,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    OPCODE_NAMES,
    REPLY,
    REQUEST,
    ZERO_IP,
    ZERO_MAC,
    ArpPacket,
    EthernetFrame,
    arp_frame,
    explain_frame,
    hex_dump,
    mac_for_ip,
)
from switch import DEFAULT_SWITCH_ADDR


@dataclass
class ArpCacheEntry:
    mac: str
    entry_type: str  # 'dynamic' or 'static'
    expiry: float    # timestamp (inf for static)

    @property
    def is_expired(self) -> bool:
        if self.entry_type == "static":
            return False
        return time.time() >= self.expiry

    def remaining_str(self) -> str:
        if self.entry_type == "static":
            return "Permanent"
        rem = max(0.0, self.expiry - time.time())
        return f"{rem:5.1f} s"


class Host:
    """Simulated Host connected to the Layer-2 switch."""

    def __init__(
        self,
        name: str,
        ip: str,
        switch_addr: tuple[str, int] = DEFAULT_SWITCH_ADDR,
        mac: str | None = None,
        cache_ttl: float = 60.0,
        timeout: float = 1.0,
        retries: int = 3,
        show_hex: bool = False,
        t0: float | None = None,
    ):
        self.name = name
        self.ip = ip
        self.mac = mac or mac_for_ip(ip)
        self.switch_addr = switch_addr
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.retries = retries
        self.show_hex = show_hex
        self.t0 = t0 if t0 is not None else time.time()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.3)

        self.cache: dict[str, ArpCacheEntry] = {}
        self.waiting_events: dict[str, threading.Event] = {}
        self.inbox: list[tuple[str, str]] = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def log(self, msg: str) -> None:
        elapsed = time.time() - self.t0
        print(f"[{elapsed:6.2f}s] [Host {self.name}] {msg}", flush=True)

    # -------------------------------------------------------------------------
    # Frame Transmission
    # -------------------------------------------------------------------------
    def send_arp(self, packet: ArpPacket, dst_mac: str) -> None:
        data = arp_frame(packet, dst_mac)
        try:
            self.sock.sendto(data, self.switch_addr)
        except OSError as exc:
            self.log(f"Socket send error: {exc}")
            return

        kind = "broadcast" if dst_mac == BROADCAST_MAC else "unicast"
        oper_name = "REQUEST" if packet.opcode == REQUEST else "REPLY"
        self.log(f"-> ARP {oper_name} ({kind}, {len(data)}B): {packet.describe()}")

        if self.show_hex:
            print(hex_dump(data) + "\n" + explain_frame(data), flush=True)

    def announce(self) -> None:
        """Broadcast Gratuitous ARP: announce own IP/MAC mapping to the subnet."""
        pkt = ArpPacket(
            opcode=REQUEST,
            sender_mac=self.mac,
            sender_ip=self.ip,
            target_mac=ZERO_MAC,
            target_ip=self.ip,
        )
        self.send_arp(pkt, BROADCAST_MAC)

    # -------------------------------------------------------------------------
    # ARP Cache Operations
    # -------------------------------------------------------------------------
    def lookup(self, ip: str) -> str | None:
        """Query the local ARP cache with automatic TTL expiration."""
        with self.lock:
            entry = self.cache.get(ip)
            if entry:
                if entry.is_expired:
                    del self.cache[ip]
                    self.log(f"ARP cache: Entry for {ip} expired and was evicted.")
                    return None
                return entry.mac
            return None

    def learn(self, ip: str, mac: str, entry_type: str = "dynamic") -> None:
        """Add or update an entry in the local ARP cache."""
        with self.lock:
            old = self.cache.get(ip)
            expiry = float("inf") if entry_type == "static" else time.time() + self.cache_ttl
            self.cache[ip] = ArpCacheEntry(mac=mac, entry_type=entry_type, expiry=expiry)

        if old is None:
            self.log(f"ARP cache: Added   {ip} -> {mac} ({entry_type})")
        elif old.mac != mac:
            self.log(f"ARP cache: Updated {ip} -> {mac} (was {old.mac})")
        else:
            self.log(f"ARP cache: Refreshed {ip} -> {mac} (TTL reset)")

    def add_static_entry(self, ip: str, mac: str) -> None:
        """Add a permanent static ARP entry (equivalent to `arp -s <ip> <mac>`)."""
        self.learn(ip, mac, entry_type="static")

    def delete_entry(self, ip: str) -> bool:
        """Delete an ARP entry (equivalent to `arp -d <ip>`)."""
        with self.lock:
            if ip in self.cache:
                del self.cache[ip]
                self.log(f"ARP cache: Deleted entry for {ip}")
                return True
        self.log(f"ARP cache: Entry {ip} not found.")
        return False

    def clear(self) -> None:
        """Flush dynamic entries from ARP cache."""
        with self.lock:
            self.cache = {ip: e for ip, e in self.cache.items() if e.entry_type == "static"}
        self.log("ARP cache: Dynamic entries flushed.")

    def table_text(self) -> str:
        """Format the ARP Cache table (similar to `arp -a`)."""
        with self.lock:
            # Purge expired entries
            expired = [ip for ip, e in self.cache.items() if e.is_expired]
            for ip in expired:
                del self.cache[ip]

            entries = list(self.cache.items())

        lines = [
            f"  ARP Table of Host {self.name} (IP: {self.ip}, MAC: {self.mac})",
            "  +-----------------+-------------------+----------+------------+",
            "  | Internet Addr   | Physical Addr     | Type     | Expires In |",
            "  +-----------------+-------------------+----------+------------+",
        ]
        if not entries:
            lines.append("  | (ARP Cache is currently empty)                              |")
        else:
            for ip, entry in sorted(entries):
                lines.append(
                    f"  | {ip:<15} | {entry.mac:<17} | {entry.entry_type:<8} | {entry.remaining_str():<10} |"
                )
        lines.append("  +-----------------+-------------------+----------+------------+")
        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Resolution & Data Transmission
    # -------------------------------------------------------------------------
    def resolve(self, target_ip: str) -> str | None:
        """
        Resolve target_ip to a MAC address:
        1. Checks local ARP Cache first.
        2. On Cache Miss: Broadcasts ARP Request over the LAN.
        3. Waits for unicast ARP reply, retrying up to self.retries times.
        """
        if target_ip == self.ip:
            return self.mac

        # Step 1: Check Local Cache
        cached_mac = self.lookup(target_ip)
        if cached_mac:
            self.log(f"ARP Cache HIT: {target_ip} is at {cached_mac} (No packets transmitted)")
            return cached_mac

        # Step 2: Cache Miss -> Broadcast ARP Request
        self.log(f"ARP Cache MISS for {target_ip}: Broadcasting ARP Request...")
        req_pkt = ArpPacket(
            opcode=REQUEST,
            sender_mac=self.mac,
            sender_ip=self.ip,
            target_mac=ZERO_MAC,
            target_ip=target_ip,
        )

        for attempt in range(1, self.retries + 1):
            event = threading.Event()
            self.waiting_events[target_ip] = event

            self.send_arp(req_pkt, BROADCAST_MAC)

            if event.wait(self.timeout):
                self.waiting_events.pop(target_ip, None)
                resolved_mac = self.lookup(target_ip)
                if resolved_mac:
                    self.log(f"ARP Resolution Success: {target_ip} -> {resolved_mac}")
                return resolved_mac

            self.log(
                f"No ARP reply for {target_ip} within {self.timeout:g}s (Attempt {attempt}/{self.retries})"
            )

        self.waiting_events.pop(target_ip, None)
        self.log(f"Destination {target_ip} is UNREACHABLE: No ARP reply received after {self.retries} attempts.")
        return None

    def send_message(self, dest_ip: str, text: str) -> bool:
        """
        Demonstrates why ARP is needed:
        Higher-layer IPv4 data cannot be transmitted until the destination MAC is resolved.
        """
        dest_mac = self.resolve(dest_ip)
        if dest_mac is None:
            self.log(f"Transmission ABORTED: Cannot send data to {dest_ip} without physical MAC.")
            return False

        payload = f"{self.ip}|{dest_ip}|{text}".encode("utf-8")
        frame = EthernetFrame(
            dst_mac=dest_mac,
            src_mac=self.mac,
            ethertype=ETHERTYPE_IPV4,
            payload=payload,
        )
        try:
            self.sock.sendto(frame.to_bytes(), self.switch_addr)
            self.log(f"-> IPv4 Data to {dest_ip} at {dest_mac}: \"{text}\"")
            return True
        except OSError as exc:
            self.log(f"Data send error: {exc}")
            return False

    # -------------------------------------------------------------------------
    # Frame Reception & Processing
    # -------------------------------------------------------------------------
    def handle_frame(self, data: bytes) -> None:
        try:
            frame = EthernetFrame.from_bytes(data)
        except ValueError:
            return

        # Layer-2 NIC filter: process only frames destined to our MAC or BROADCAST
        if frame.dst_mac not in (self.mac, BROADCAST_MAC):
            return

        # Handle Layer-3 IPv4 Data Frame
        if frame.ethertype == ETHERTYPE_IPV4:
            try:
                src_ip, _dst_ip, text = frame.payload.decode("utf-8", errors="replace").split("|", 2)
                self.inbox.append((src_ip, text))
                self.log(f"<- IPv4 Data received from {src_ip}: \"{text}\"")
            except Exception:
                pass
            return

        if frame.ethertype != ETHERTYPE_ARP:
            return

        arp = ArpPacket.from_bytes(frame.payload)
        self.log(f"<- ARP Frame received: {arp.describe()}")

        # IP Address Conflict Detection
        if arp.sender_ip == self.ip and arp.sender_mac != self.mac:
            self.log(
                f"!! [CRITICAL] IP ADDRESS CONFLICT DETECTED: {arp.sender_mac} is also claiming our IP {self.ip}!"
            )
            return

        with self.lock:
            already_known = arp.sender_ip in self.cache

        # 1. ARP Request targeted to our IP:
        if arp.opcode == REQUEST and arp.target_ip == self.ip and not arp.is_gratuitous:
            # RFC 826: Learn the requester's IP & MAC immediately!
            self.learn(arp.sender_ip, arp.sender_mac)

            # Reply unicast to the requester
            reply = ArpPacket(
                opcode=REPLY,
                sender_mac=self.mac,
                sender_ip=self.ip,
                target_mac=arp.sender_mac,
                target_ip=arp.sender_ip,
            )
            self.send_arp(reply, arp.sender_mac)

        # 2. ARP Reply targeted to us:
        elif arp.opcode == REPLY and arp.target_ip == self.ip:
            self.learn(arp.sender_ip, arp.sender_mac)
            event = self.waiting_events.get(arp.sender_ip)
            if event:
                event.set()

        # 3. Packet from known host: refresh our existing entry (RFC 826)
        elif already_known:
            self.learn(arp.sender_ip, arp.sender_mac)
        else:
            self.log("   Not targeted to our IP -> Packet ignored (NIC drops payload).")

    def receive_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                data, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                if self.stop_event.is_set():
                    break
                continue

            try:
                self.handle_frame(data)
            except ValueError as err:
                self.log(f"Frame decode error: {err}")

    def start(self, announce: bool = True) -> "Host":
        threading.Thread(target=self.receive_loop, daemon=True).start()
        self.log(f"Online: Interface {self.ip} [{self.mac}] connected to switch.")
        if announce:
            self.announce()
        return self

    def stop(self) -> None:
        self.stop_event.set()
        try:
            self.sock.close()
        except OSError:
            pass


HELP_TEXT = """
Available Commands:
  arp <ip>                 - Resolve target IPv4 address to MAC (checks cache, else ARP request)
  send <ip> <message>      - Send IPv4 data message to target host (resolves ARP first)
  table  (or arp -a)       - Display local ARP Cache Table
  add <ip> <mac>           - Add static permanent ARP entry (or: arp -s <ip> <mac>)
  del <ip>                 - Delete an entry from ARP Cache (or: arp -d <ip>)
  clear                    - Flush dynamic ARP cache entries
  gratuitous               - Broadcast Gratuitous ARP announcement
  help                     - Show this command reference
  quit (or exit)           - Shut down this host
"""


def interactive_cli(host: Host) -> None:
    print(f"\n=======================================================")
    print(f"  ARP Host '{host.name}' Shell (IP: {host.ip}, MAC: {host.mac})")
    print(f"  Connected to Switch: {host.switch_addr[0]}:{host.switch_addr[1]}")
    print(f"=======================================================")
    print(HELP_TEXT, flush=True)

    while True:
        try:
            line = input(f"{host.name}> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if not line:
            continue

        parts = line.split(maxsplit=2)
        cmd = parts[0].lower()

        try:
            if cmd in ("quit", "exit"):
                break
            elif cmd == "help":
                print(HELP_TEXT, flush=True)
            elif cmd == "arp" and len(parts) >= 2:
                if parts[1] == "-a":
                    print(host.table_text(), flush=True)
                elif parts[1] == "-s" and len(parts) == 4:
                    host.add_static_entry(parts[2], parts[3])
                elif parts[1] == "-d" and len(parts) == 3:
                    host.delete_entry(parts[2])
                else:
                    mac = host.resolve(parts[1])
                    print(f"  Result: {parts[1]} -> {mac or 'Host Unreachable'}", flush=True)
            elif cmd == "send" and len(parts) == 3:
                host.send_message(parts[1], parts[2])
            elif cmd in ("table", "cache"):
                print(host.table_text(), flush=True)
            elif cmd == "add" and len(parts) == 3:
                host.add_static_entry(parts[1], parts[2])
            elif cmd == "del" and len(parts) == 2:
                host.delete_entry(parts[1])
            elif cmd == "clear":
                host.clear()
            elif cmd == "gratuitous":
                host.announce()
            else:
                print("Unknown command. Type 'help' for available commands.", flush=True)
        except Exception as exc:
            print(f"Error: {exc}", flush=True)

    host.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Ethernet Host on Simulated LAN")
    parser.add_argument("--name", required=True, help="Host identifier (e.g. A, B, C)")
    parser.add_argument("--ip", required=True, help="Host IPv4 address (e.g. 192.168.1.10)")
    parser.add_argument("--mac", help="Host MAC address (default: deterministic 02:00:c0:...)")
    parser.add_argument("--switch-port", type=int, default=DEFAULT_SWITCH_ADDR[1], help="Switch UDP port")
    parser.add_argument("--ttl", type=float, default=60.0, help="ARP Cache TTL in seconds")
    parser.add_argument("--hex", action="store_true", help="Print 42-byte hex dump for every frame")
    args = parser.parse_args()

    host = Host(
        name=args.name,
        ip=args.ip,
        switch_addr=("127.0.0.1", args.switch_port),
        mac=args.mac,
        cache_ttl=args.ttl,
        show_hex=args.hex,
    )
    host.start()
    interactive_cli(host)


if __name__ == "__main__":
    main()

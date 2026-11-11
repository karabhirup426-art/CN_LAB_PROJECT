"""
switch.py
Layer-2 Learning Ethernet Switch over UDP Sockets
=================================================
Course: CSE/PC/B/S/314 Computer Networks Laboratory
Basket 1: Address Resolution Protocol (ARP)
Author: Sk Amanullah (skaman75)

WHY A SIMULATED SWITCH:
  Real Ethernet switches forward frames directly across physical RJ-45 ports.
  Operating systems require root/administrator privileges and raw packet drivers
  (e.g., WinPcap/Npcap) to inject raw Ethernet frames.
  This switch acts as the Layer-2 collision domain / broadcast domain. Each host
  connects via an ephemeral UDP socket, which the switch treats as a physical port.

SWITCH FORWARDING LOGIC (IEEE 802.1D Learning Switch):
  1. Address Learning:
     Examines source MAC of each incoming frame. Records:
       Source MAC -> Ingress Port (UDP address) in the Switch MAC Table.
  2. Frame Forwarding:
     - Destination MAC is BROADCAST (ff:ff:ff:ff:ff:ff):
       Floods frame to every port EXCEPT the ingress port.
     - Destination MAC is KNOWN UNICAST:
       Forwards frame directly to the mapped destination port only.
     - Destination MAC is UNKNOWN UNICAST:
       Floods frame to all other ports (unknown unicast flooding).
"""

import argparse
import socket
import sys
import threading
import time

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from arp_packet import BROADCAST_MAC, ETHERTYPE_ARP, ArpPacket, EthernetFrame

DEFAULT_SWITCH_ADDR = ("127.0.0.1", 9000)


class Switch:
    """Simulated Layer-2 Ethernet Learning Switch."""

    def __init__(self, addr: tuple[str, int] = DEFAULT_SWITCH_ADDR, quiet: bool = False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addr)
        self.sock.settimeout(0.3)
        self.addr = self.sock.getsockname()
        self.quiet = quiet
        self.mac_table: dict[str, tuple[str, int]] = {}     # MAC -> UDP (host port)
        self.port_numbers: dict[tuple[str, int], int] = {}  # UDP -> Port 1, 2, 3...
        self.stop_event = threading.Event()
        self.t0 = time.time()

    def log(self, msg: str) -> None:
        if not self.quiet:
            elapsed = time.time() - self.t0
            print(f"[{elapsed:6.2f}s] [Switch] {msg}", flush=True)

    def port_str(self, addr: tuple[str, int]) -> str:
        """Assign human-readable port numbers 1, 2, 3... to client endpoints."""
        if addr not in self.port_numbers:
            self.port_numbers[addr] = len(self.port_numbers) + 1
        return f"Port {self.port_numbers[addr]}"

    def handle_frame(self, data: bytes, addr: tuple[str, int]) -> None:
        """Process an incoming Ethernet frame according to IEEE 802.1D learning switch rules."""
        try:
            frame = EthernetFrame.from_bytes(data)
        except ValueError:
            return  # Drop malformed / non-Ethernet payloads

        # Step 1: Learning - Record source MAC -> Ingress Port
        if self.mac_table.get(frame.src_mac) != addr:
            self.mac_table[frame.src_mac] = addr
            self.log(f"Learned {frame.src_mac} on {self.port_str(addr)} ({addr[0]}:{addr[1]})")

        # Wireshark-like frame descriptor
        what = "IPv4 Data"
        if frame.ethertype == ETHERTYPE_ARP:
            try:
                what = ArpPacket.from_bytes(frame.payload).describe()
            except ValueError:
                what = "ARP Packet"

        # Step 2: Forwarding Decision
        if frame.dst_mac == BROADCAST_MAC:
            out_ports = [a for a in set(self.mac_table.values()) if a != addr]
            self.log(
                f"Broadcast from {self.port_str(addr)} -> Flooding to {len(out_ports)} port(s) [{what}]"
            )
        elif frame.dst_mac in self.mac_table:
            dest_addr = self.mac_table[frame.dst_mac]
            out_ports = [dest_addr]
            self.log(
                f"Unicast: {self.port_str(addr)} -> {self.port_str(dest_addr)} only [{what}]"
            )
        else:
            out_ports = [a for a in set(self.mac_table.values()) if a != addr]
            self.log(
                f"Unknown unicast {frame.dst_mac} -> Flooding to {len(out_ports)} port(s)"
            )

        # Transmit to determined destination ports
        for out_addr in out_ports:
            try:
                self.sock.sendto(data, out_addr)
            except OSError:
                pass

    def table_text(self) -> str:
        """Display the Switch MAC Address Table."""
        lines = [
            "  +-------------------+--------+-------------------+",
            "  | MAC Address       | Port   | UDP Endpoint      |",
            "  +-------------------+--------+-------------------+",
        ]
        if not self.mac_table:
            lines.append("  | (MAC Table is currently empty)                 |")
        else:
            for mac, addr in sorted(self.mac_table.items()):
                p = self.port_str(addr)
                ep = f"{addr[0]}:{addr[1]}"
                lines.append(f"  | {mac:<17} | {p:<6} | {ep:<17} |")
        lines.append("  +-------------------+--------+-------------------+")
        return "\n".join(lines)

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                continue
            self.handle_frame(data, addr)

        try:
            self.sock.close()
        except OSError:
            pass

    def start(self) -> "Switch":
        threading.Thread(target=self.run, daemon=True).start()
        return self

    def stop(self) -> None:
        self.stop_event.set()


def main() -> None:
    parser = argparse.ArgumentParser(description="Layer-2 Learning Switch for ARP Hosts")
    parser.add_argument("--port", type=int, default=DEFAULT_SWITCH_ADDR[1], help="Switch UDP port")
    args = parser.parse_args()

    sw = Switch(("127.0.0.1", args.port))
    print(f"\n=======================================================")
    print(f"  Layer-2 Ethernet Learning Switch running on UDP {sw.addr[0]}:{sw.addr[1]}")
    print(f"  Floods broadcasts, forwards unicast, learns source MACs")
    print(f"  Press Ctrl+C to terminate switch.")
    print(f"=======================================================\n", flush=True)

    try:
        sw.run()
    except KeyboardInterrupt:
        print("\n\nSwitch terminating. Final MAC Table:\n" + sw.table_text())


if __name__ == "__main__":
    main()
